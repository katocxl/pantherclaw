// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/provisioning/app"
	"github.com/katocxl/pantherclaw/internal/provisioning/domain"
	"github.com/katocxl/pantherclaw/internal/provisioning/ports"
)

// The core half of HR-634 (D562): the protocol code verifies a response
// and hands the core what it says; the core decides which org, connection
// and page the sign-in is for, and lets a consumed request finish once,
// after its assertion id was recorded. stubVerifier stands in for the
// protocol code's verification.

// stubVerifier is a response the protocol code has verified: its assertion
// id, lifetime and identity. A real response could also name an org,
// connection or page; the core takes none of them from it.
type stubVerifier struct {
	id           string
	notOnOrAfter time.Time
	verified     ports.Verified
}

// samlRig is an ACTIVE SAML connection of e's org and the core's SignIn.
type samlRig struct {
	e    *env
	si   *app.SignIn
	w    *web
	conn ids.UUID
}

func newSAMLRig(t *testing.T, e *env, name, entity string) *samlRig {
	t.Helper()
	c, f, err := e.svc.CreateConnection(e.admin(e.alice), domain.Connection{
		Name: name, EntityID: entity, SSOURL: "https://saml.example.com/sso", Certificates: []string{testCert(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.confirm(t, f, e.bob); err != nil {
		t.Fatal(err)
	}
	w := &web{}
	si := &app.SignIn{Pool: e.pool, Browser: authnapp.NewBrowser(e.pool, "https://pc.example.test", nil, clock.System{}, nil), Web: w}
	return &samlRig{e: e, si: si, w: w, conn: c.ID}
}

// consume starts and consumes one sign-in, returning the core's handle.
func (g *samlRig) consume(t *testing.T, req, next string) ports.SignInHandle {
	t.Helper()
	ctx := context.Background()
	st, err := g.si.StartSignIn(ctx, g.e.org.String(), g.conn.String(), req, next, "")
	if err != nil {
		t.Fatal(err)
	}
	p, err := g.si.ConsumeSignIn(ctx, g.e.org.String(), g.conn.String(), st.RelayState, st.Binding)
	if err != nil || p.RequestID != req || p.Handle == nil {
		t.Fatalf("consumed %+v %v", p, err)
	}
	return p.Handle
}

// acs is what the protocol code does with a verified response: record its
// assertion id, then finish with the handle.
func (g *samlRig) acs(t *testing.T, h ports.SignInHandle, v stubVerifier) error {
	t.Helper()
	if err := g.si.RecordAssertion(context.Background(), h, v.id, v.notOnOrAfter); err != nil {
		return err
	}
	g.finish(h, v.verified)
	return nil
}

func (g *samlRig) finish(h ports.SignInHandle, v ports.Verified) {
	*g.w = web{}
	g.si.FinishSignIn(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/app/ext/saml/acs", nil), h, v)
}

func (g *samlRig) signedIn(t *testing.T) authnapp.BrowserSignIn {
	t.Helper()
	if g.w.err != nil || g.w.out.Reason != "" || g.w.out.Secret == "" {
		t.Fatalf("not signed in: %+v %v", g.w.out, g.w.err)
	}
	return g.w.out
}

func (g *samlRig) refused(t *testing.T, what string) {
	t.Helper()
	if !errors.Is(g.w.err, authnapp.ErrSignInUnavailable) || g.w.out.Secret != "" {
		t.Fatalf("%s: %+v %v", what, g.w.out, g.w.err)
	}
}

func (e *env) samlUser(t *testing.T, entity, subject string) ids.UUID {
	t.Helper()
	u := ids.NewV7()
	e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, $3, $4)", e.org, u, "saml:"+entity, subject)
	return u
}

func (e *env) sessionUser(t *testing.T, session ids.UUID) ids.UUID {
	t.Helper()
	var u ids.UUID
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT user_id FROM pc.sessions WHERE org_id = $1 AND id = $2", e.org, session).Scan(&u)
	}); err != nil {
		t.Fatal(err)
	}
	return u
}

func valid(id, subject string) stubVerifier {
	return stubVerifier{id: id, notOnOrAfter: time.Now().Add(5 * time.Minute), verified: ports.Verified{Subject: subject}}
}

// TestHR634_TargetComesFromTheHandle: the org, connection and page of a
// sign-in are the consumed request's, never the response's. Two
// connections of one org each have a user "frank"; a response finished
// with the first connection's handle signs in the first one's frank, at
// the page the request asked for.
//
// Covers: F922
func TestHR634_TargetComesFromTheHandle(t *testing.T) {
	e := newEnv(t)
	okta := newSAMLRig(t, e, "okta", entityID)
	other := newSAMLRig(t, e, "other", "https://saml.other.example.com/entity")
	frank := e.samlUser(t, entityID, "frank")
	otherFrank := e.samlUser(t, "https://saml.other.example.com/entity", "frank")

	if err := okta.acs(t, okta.consume(t, "_t1", "/app/agents"), valid("_t1a", "frank")); err != nil {
		t.Fatal(err)
	}
	out := okta.signedIn(t)
	if out.Org != e.org || out.Next != "/app/agents" || e.sessionUser(t, out.Session) != frank {
		t.Fatalf("signed in %+v as %s", out, e.sessionUser(t, out.Session))
	}
	if err := other.acs(t, other.consume(t, "_t2", "/app/"), valid("_t2a", "frank")); err != nil {
		t.Fatal(err)
	}
	out = other.signedIn(t)
	if out.Next != "/app/" || e.sessionUser(t, out.Session) != otherFrank {
		t.Fatalf("signed in %+v as %s", out, e.sessionUser(t, out.Session))
	}
	// A handle the core did not make carries no target at all.
	if err := okta.si.RecordAssertion(context.Background(), forged{}, "_t3a", time.Now().Add(time.Minute)); !errors.Is(err, ports.ErrSignInUnavailable) {
		t.Fatalf("a forged handle recorded: %v", err)
	}
	okta.finish(forged{}, ports.Verified{Subject: "frank"})
	okta.refused(t, "a forged handle")
}

// TestHR634_HandleFinishesOnce: a consumed request finishes once; a second
// finish with the same handle is refused, and the handle takes no other
// assertion.
//
// Covers: F922
func TestHR634_HandleFinishesOnce(t *testing.T) {
	e := newEnv(t)
	g := newSAMLRig(t, e, "okta", entityID)
	e.samlUser(t, entityID, "frank")
	h := g.consume(t, "_o1", "/app/")
	if err := g.acs(t, h, valid("_o1a", "frank")); err != nil {
		t.Fatal(err)
	}
	g.signedIn(t)
	g.finish(h, ports.Verified{Subject: "frank"})
	g.refused(t, "a second finish")
	if err := g.si.RecordAssertion(context.Background(), h, "_o1b", time.Now().Add(time.Minute)); !errors.Is(err, ports.ErrReplayed) {
		t.Fatalf("a finished handle recorded another assertion: %v", err)
	}
}

// TestHR634_FinishesOnlyAfterTheAssertionIsRecorded: a handle whose
// assertion id was not recorded does not finish, and is spent by trying.
//
// Covers: F922
func TestHR634_FinishesOnlyAfterTheAssertionIsRecorded(t *testing.T) {
	e := newEnv(t)
	g := newSAMLRig(t, e, "okta", entityID)
	e.samlUser(t, entityID, "frank")
	h := g.consume(t, "_r1", "/app/")
	g.finish(h, ports.Verified{Subject: "frank"})
	g.refused(t, "an unrecorded finish")
	if err := g.acs(t, h, valid("_r1a", "frank")); !errors.Is(err, ports.ErrReplayed) {
		t.Fatalf("recorded after a refused finish: %v", err)
	}
	if g.w.out.Secret != "" {
		t.Fatal("signed in after a refused finish")
	}
	// A recorded assertion that is already over is not recorded.
	h = g.consume(t, "_r2", "/app/")
	if err := g.si.RecordAssertion(context.Background(), h, "_r2a", time.Now().Add(-time.Second)); !errors.Is(err, ports.ErrReplayed) {
		t.Fatalf("an expired assertion was recorded: %v", err)
	}
	g.finish(h, ports.Verified{Subject: "frank"})
	g.refused(t, "a finish after a refused record")
}

// TestHR634_AssertionIDOnce: an assertion id is accepted once per
// connection, across sign-ins: a response replayed into a fresh sign-in
// is refused and signs nobody in.
//
// Covers: F922
func TestHR634_AssertionIDOnce(t *testing.T) {
	e := newEnv(t)
	g := newSAMLRig(t, e, "okta", entityID)
	e.samlUser(t, entityID, "frank")
	resp := valid("_same", "frank")
	if err := g.acs(t, g.consume(t, "_a1", "/app/"), resp); err != nil {
		t.Fatal(err)
	}
	g.signedIn(t)
	*g.w = web{}
	if err := g.acs(t, g.consume(t, "_a2", "/app/"), resp); !errors.Is(err, ports.ErrReplayed) {
		t.Fatalf("a replayed assertion id: %v", err)
	}
	if g.w.out.Secret != "" {
		t.Fatal("a replayed assertion signed in")
	}
}

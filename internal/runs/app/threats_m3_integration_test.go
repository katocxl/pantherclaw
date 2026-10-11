// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	"github.com/katocxl/pantherclaw/internal/authn/oidctest"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/runs/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const m3tAudience = "https://pc.example.test"

// m3tProvider configures idp as an OIDC provider; with an audience it
// accepts subject tokens, without one it is for sign-in only.
func m3tProvider(t *testing.T, name string, idp *oidctest.Provider, audience string) *oidcrp.Provider {
	t.Helper()
	p, err := oidcrp.New(oidcrp.Config{
		Name: name, Issuer: idp.Issuer(), ClientID: idp.ClientID, ClientSecret: pclog.NewSecret([]byte(idp.ClientSecret)),
		AllowInsecureLoopback: true, HTTPClient: idp.Client(), SubjectTokenAudience: audience,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// m3tSubject is a subject token for sub signed by idp under iss.
func m3tSubject(idp *oidctest.Provider, iss, sub, aud string, issued, lifetime time.Duration) string {
	now := time.Now()
	return idp.Token(map[string]any{
		"iss": iss, "sub": sub, "aud": aud, "jti": ids.NewV7().String(),
		"iat": now.Add(-issued).Unix(), "exp": now.Add(-issued + lifetime).Unix(),
	}, "")
}

// m3tServiceAccountGrant inserts an active root grant whose principal is
// the service account sa, issued by the world's owner.
func m3tServiceAccountGrant(t *testing.T, w *world, agent, sa ids.UUID) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	w.exec(t, `INSERT INTO pc.grants (org_id, id, agent_id, principal_sa_id, environment_id, depth, current_revision,
		grantor_kind, grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $6, 'test')`, w.org, id, agent, sa, w.env, w.owner)
	w.exec(t, `INSERT INTO pc.grant_revisions (org_id, id, grant_id, revision, not_before, expires_at, bounds, requirements, limits,
		delegation_depth, max_children, min_attestation, widens, created_by)
		VALUES ($1, $2, $3, 1, now() - interval '1 hour', now() + interval '2 hours',
		convert_to('{"operations":["payments.refund.create"]}', 'UTF8'), convert_to('[]', 'UTF8'), convert_to('{}', 'UTF8'),
		0, 0, 0, false, 'test')`, w.org, ids.NewV7(), id)
	w.exec(t, "INSERT INTO pc.grant_lineage (org_id, grant_id, ancestor_id, distance) VALUES ($1, $2, $2, 0)", w.org, id)
	return id
}

// TestT048_RepresentedPrincipalsCannotBeSpoofed: T-048 — a portal's
// service account holding run.represent, and a colleague without it, try
// to start runs in alice's name. Nothing in a request names a principal, so
// only a subject token can, and these are refused without starting a run:
// a token from an unconfigured provider, one forged under the configured
// provider's issuer, one from a provider configured for sign-in only, one
// for another audience (alice's sign-in ID token among them), a stale or
// expired one, one replayed by another launcher, and one for a user of
// another org. A run represents alice only with her fresh token, and the
// token never adds authority: the run has no grant, and neither the
// launcher's own grant nor bob's can be bound to it. TestHR146_* and the
// oidcrp tests cover the single checks.
func TestT048_RepresentedPrincipalsCannotBeSpoofed(t *testing.T) {
	w := newWorld(t)
	w.svc.WithGrants(&grantspg.Store{Pool: w.pool})
	corp, login, rogue := oidctest.New(t), oidctest.New(t), oidctest.New(t)
	svc := w.svc.WithSubjects(oidcrp.Subjects{
		m3tProvider(t, "corp", corp, m3tAudience), m3tProvider(t, "login", login, ""),
	})
	alice, bob := ids.NewV7(), ids.NewV7()
	w.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, $3, 'alice'), ($1, $4, $3, 'bob')",
		w.org, alice, corp.Issuer(), bob)
	w.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, $3, 'alice'), ($1, $4, $5, 'alice')",
		w.org, ids.NewV7(), login.Issuer(), ids.NewV7(), rogue.Issuer())
	o := newWorld(t)
	o.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, $3, 'dave')", o.org, ids.NewV7(), corp.Issuer())
	portal, kiosk := ids.NewV7(), ids.NewV7()
	w.exec(t, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'portal', 'test'), ($1, $3, 'kiosk', 'test')",
		w.org, portal, kiosk)
	launcher := w.as(td.KindServiceAccount, portal, td.RoleRunLauncher)
	agent := w.agent(t)
	start := func(ctx context.Context, tok string, grant *ids.UUID) (app.Run, error) {
		return svc.StartRun(ctx, app.StartInput{AgentID: agent, SubjectToken: tok, SubjectTokenType: app.SubjectIDToken, GrantID: grant})
	}
	fresh := func(sub string) string { return m3tSubject(corp, corp.Issuer(), sub, m3tAudience, 0, 5*time.Minute) }

	r, err := svc.StartRun(w.as(td.KindUser, bob, td.RoleDeveloper), app.StartInput{AgentID: agent})
	if err != nil || r.Principal != (app.Actor{Kind: "user", ID: bob.String()}) || r.PrincipalSource != app.SourceLauncher {
		t.Fatalf("bob without a token: %+v, %v", r, err)
	}
	_, err = start(w.as(td.KindUser, bob, td.RoleDeveloper), fresh("alice"), nil)
	wantCode(t, "bob with alice's token but without run.represent", err, pcerr.PermissionDenied, "")
	used := fresh("alice")
	if r, err := start(launcher, used, nil); err != nil || r.Principal != (app.Actor{Kind: "user", ID: alice.String()}) || r.GrantID != nil {
		t.Fatalf("alice's fresh token: %+v, %v", r, err)
	}
	for _, tc := range []struct {
		name string
		as   context.Context
		tok  string
	}{
		{"a token from an unconfigured provider", launcher, m3tSubject(rogue, rogue.Issuer(), "alice", m3tAudience, 0, 5*time.Minute)},
		{"a token forged under the configured issuer", launcher, m3tSubject(rogue, corp.Issuer(), "alice", m3tAudience, 0, 5*time.Minute)},
		{"a token from a sign-in-only provider", launcher, m3tSubject(login, login.Issuer(), "alice", m3tAudience, 0, 5*time.Minute)},
		{"a token for another audience", launcher, m3tSubject(corp, corp.Issuer(), "alice", "https://wiki.example.test", 0, 5*time.Minute)},
		{"alice's sign-in ID token", launcher, m3tSubject(corp, corp.Issuer(), "alice", corp.ClientID, 0, 5*time.Minute)},
		{"a token issued six minutes ago", launcher, m3tSubject(corp, corp.Issuer(), "alice", m3tAudience, 6*time.Minute, 10*time.Minute)},
		{"an expired token", launcher, m3tSubject(corp, corp.Issuer(), "alice", m3tAudience, 2*time.Minute, time.Minute)},
		{"a used token replayed by another launcher", w.as(td.KindServiceAccount, kiosk, td.RoleRunLauncher), used},
		{"a user of another org", launcher, fresh("dave")},
	} {
		_, err := start(tc.as, tc.tok, nil)
		wantCode(t, tc.name, err, pcerr.PermissionDenied, "SUBJECT_TOKEN")
	}

	own := m3tServiceAccountGrant(t, w, agent, portal)
	if r, err := svc.StartRun(launcher, app.StartInput{AgentID: agent, GrantID: &own}); err != nil || r.GrantID == nil || *r.GrantID != own {
		t.Fatalf("the portal's own grant for its own run: %+v, %v", r, err)
	}
	none := ids.UUID{}
	bobs := w.grant(t, agent, bob, none, none, "-1 hour", "2 hours", false)
	for name, g := range map[string]ids.UUID{"the launcher's own grant": own, "bob's grant": bobs} {
		_, err := start(launcher, fresh("alice"), &g)
		wantCode(t, name+" on alice's run", err, pcerr.FailedPrecondition, "GRANT_MISMATCH")
	}
	if n := w.count(t, "SELECT count(*) FROM pc.runs WHERE org_id = $1", w.org); n != 3 {
		t.Errorf("runs %d, want bob's, alice's and the portal's", n)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.runs WHERE org_id = $1 AND principal_user_id = $2 AND grant_id IS NOT NULL", w.org, alice); n != 0 {
		t.Errorf("%d of alice's runs carry a grant", n)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.grants WHERE org_id = $1", w.org); n != 2 {
		t.Errorf("grants %d: a subject token created one", n)
	}
}

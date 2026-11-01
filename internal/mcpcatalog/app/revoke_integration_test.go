// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/mcpcatalog/app"
	"github.com/katocxl/pantherclaw/internal/mcpcatalog/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const revokedHost = "mcp.example.test"

// revokeServer previews and revokes as a person.
func (e *env) revokeServer(t *testing.T, who person, id ids.UUID) app.RevokeResult {
	t.Helper()
	p, err := e.svc.PreviewRevoke(who.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.svc.RevokeServer(who.ctx, id, p.Digest, "compromised upstream")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (e *env) decide(t *testing.T, plan, reviewer ids.UUID) (string, error) {
	t.Helper()
	var state string
	err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		state, _, err = e.cont.DecideRestorationIn(ctx, tx, plan, reviewer, true)
		return err
	})
	return state, err
}

func (e *env) liveControls(t *testing.T) int64 {
	t.Helper()
	return e.int64(t, `SELECT count(*) FROM pc.containment_controls WHERE org_id = $1 AND lifted_at IS NULL AND control = 'DENY_ALL'
		AND scope_type = 'connection'`, e.org)
}

func (e *env) serverStatus(t *testing.T, id ids.UUID) domain.Status {
	t.Helper()
	var out dbq.PcMcpServer
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).GetMcpServer(ctx, e.org, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return domain.Status(out.Status)
}

func (e *env) versionState(t *testing.T) string {
	t.Helper()
	var state string
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT state FROM pc.package_versions WHERE org_id = $1 AND version = '1.0.0'", e.org).Scan(&state)
	}); err != nil {
		t.Fatal(err)
	}
	return state
}

// withPackage is a server that names the org's tool package as well.
func (e *env) withPackage(t *testing.T) dbq.PcMcpServer {
	t.Helper()
	s, err := e.svc.Propose(e.alice.ctx, domain.Proposal{
		Name: "payments", Title: "Payments", Transport: domain.TransportHTTP, Spec: domain.Spec{Host: revokedHost, PackageRef: mcpPackage},
	})
	if err != nil {
		t.Fatal(err)
	}
	if s, err = e.svc.Approve(e.alice.ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestF875_ARevokeStopsEveryMatchOfItsOrg: one transaction adds a DENY_ALL per
// matching connection through the response service, whatever the connection's
// state, leaves the connections' own state alone so one Restore cannot undo
// it, quarantines the package's versions, raises the epoch and stops at the
// org's edge (HR-587).
//
// Covers: F875
func TestF875_ARevokeStopsEveryMatchOfItsOrg(t *testing.T) {
	e := newEnv(t)
	s := e.withPackage(t)
	a := e.mustCreate(t, "a", "https://"+revokedHost+"/one")
	b := e.mustCreate(t, "b", "https://"+revokedHost+"/two")
	other := e.mustCreate(t, "other", "https://elsewhere.example.test/mcp")
	theirs := e.withOrg(t, "theirs")
	mine := theirs.mustCreate(t, "same-url", "https://"+revokedHost+"/one")
	before := e.epoch(t)

	p, err := e.svc.PreviewRevoke(e.alice.ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Connections) != 2 || len(p.Versions) != 1 || len(p.Digest) != 32 {
		t.Fatalf("preview %+v", p)
	}
	r, err := e.svc.RevokeServer(e.alice.ctx, s.ID, p.Digest, "compromised upstream")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Controls) != 2 || len(r.Plans) != 1 || r.Action.IsZero() {
		t.Fatalf("revoke %+v", r)
	}
	if got := e.serverStatus(t, s.ID); got != domain.StatusRevoked {
		t.Fatalf("status %s", got)
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.containment_controls WHERE org_id = $1 AND action_id = $2 AND scope_type = 'connection'
		AND control = 'DENY_ALL' AND scope_id = ANY($3::text[])`, e.org, r.Action, []string{a.ID.String(), b.ID.String()}); n != 2 {
		t.Fatalf("controls on the matches: %d", n)
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.response_actions WHERE org_id = $1 AND id = $2 AND scope_type = 'mcp_server' AND scope_id = $3
		AND preview_digest = $4`, e.org, r.Action, s.ID.String(), p.Digest); n != 1 {
		t.Fatal("the action does not name the server and its digest")
	}
	if got := e.state(t, a.ID).State; got != capp.StateActive {
		t.Fatalf("a revoke is a control, not a connection state: %s", got)
	}
	if got := e.state(t, other.ID).State; got != capp.StateActive || e.liveControls(t) != 2 {
		t.Fatalf("a non-match was touched: %s, %d", got, e.liveControls(t))
	}
	if got := e.versionState(t); got != "QUARANTINED" {
		t.Fatalf("version %s", got)
	}
	if after := e.epoch(t); after <= before {
		t.Fatalf("epoch %d, was %d", after, before)
	}
	if got := theirs.state(t, mine.ID).State; got != capp.StateActive || theirs.liveControls(t) != 0 || theirs.versionState(t) != "ACTIVE" {
		t.Fatalf("the revoke crossed orgs: %s %d", got, theirs.liveControls(t))
	}
}

// TestHR587_ARevokeNeedsAPersonAndACurrentDigest: no service account, no
// step-up, no stale digest; a refused revoke changes nothing. It stops only;
// a preview of a revoked server has nothing to say.
//
// Covers: F875
func TestHR587_ARevokeNeedsAPersonAndACurrentDigest(t *testing.T) {
	e := newEnv(t)
	s := e.approved(t, "good", revokedHost, "")
	conn := e.mustCreate(t, "a", "https://"+revokedHost+"/x")
	p, err := e.svc.PreviewRevoke(e.alice.ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := e.svc.RevokeServer(e.as(e.alice.id, td.RoleSecurityAdmin), s.ID, p.Digest, "x"); !is(err, rapp.ErrStepUp) {
		t.Fatalf("no step-up: %v", err)
	}
	sa := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	if _, err := e.svc.RevokeServer(sa, s.ID, p.Digest, "x"); !is(err, app.ErrHuman) {
		t.Fatalf("a service account: %v", err)
	}
	if _, err := e.svc.RevokeServer(e.alice.ctx, s.ID, nil, "x"); !is(err, app.ErrPreviewStale) {
		t.Fatalf("no digest: %v", err)
	}
	if _, err := e.svc.RevokeServer(e.alice.ctx, s.ID, p.Digest, ""); !is(err, app.ErrRevokeReason) {
		t.Fatalf("no reason: %v", err)
	}

	// A new match after the preview means the preview no longer says it all.
	e.mustCreate(t, "b", "https://"+revokedHost+"/y")
	if _, err := e.svc.RevokeServer(e.alice.ctx, s.ID, p.Digest, "x"); !is(err, app.ErrPreviewStale) {
		t.Fatalf("stale: %v", err)
	}
	if got := e.serverStatus(t, s.ID); got != domain.StatusApproved || e.liveControls(t) != 0 {
		t.Fatalf("a refused revoke changed something: %s %d", got, e.liveControls(t))
	}
	if got := e.state(t, conn.ID).State; got != capp.StateActive {
		t.Fatal(got)
	}

	e.revokeServer(t, e.alice, s.ID)
	if _, err := e.svc.PreviewRevoke(e.alice.ctx, s.ID); !is(err, app.ErrStatus) {
		t.Fatalf("revoked twice: %v", err)
	}
	if _, err := e.svc.RevokeServer(e.alice.ctx, ids.NewV7(), p.Digest, "x"); !is(err, app.ErrNotFound) {
		t.Fatalf("not found: %v", err)
	}
}

// TestF876_ALiftIsIndependentAndTrustIsItsOwnDecision: the person who revoked
// never lifts. Someone else's lift restores the connections and nothing more:
// the server stays REVOKED, the version stays QUARANTINED, and approving again
// waits for the last control, then needs a step-up (HR-587).
//
// Covers: F876
func TestF876_ALiftIsIndependentAndTrustIsItsOwnDecision(t *testing.T) {
	e := newEnv(t)
	s := e.withPackage(t)
	e.mustCreate(t, "a", "https://"+revokedHost+"/x")
	r := e.revokeServer(t, e.alice, s.ID)

	if _, err := e.svc.Approve(e.bob.ctx, s.ID); !is(err, app.ErrRevocationActive) {
		t.Fatalf("approve with a live control: %v", err)
	}
	if _, err := e.decide(t, r.Plans[0], e.alice.id); !is(err, rapp.ErrReviewerNotIndependent) {
		t.Fatalf("the revoker's own lift: %v", err)
	}
	if n := e.liveControls(t); n != 1 {
		t.Fatalf("live controls %d", n)
	}
	if state, err := e.decide(t, r.Plans[0], e.bob.id); err != nil || state != rapp.PlanCompleted {
		t.Fatalf("a second person: %s %v", state, err)
	}
	if n := e.liveControls(t); n != 0 {
		t.Fatalf("live controls after the lift: %d", n)
	}
	if got := e.serverStatus(t, s.ID); got != domain.StatusRevoked {
		t.Fatalf("a lift changed the server: %s", got)
	}
	if got := e.versionState(t); got != "QUARANTINED" {
		t.Fatalf("a lift restored a version: %s", got)
	}

	if _, err := e.svc.Approve(e.as(e.bob.id, td.RoleSecurityAdmin), s.ID); !is(err, rapp.ErrStepUp) {
		t.Fatalf("approve without a step-up: %v", err)
	}
	if got, err := e.svc.Approve(e.bob.ctx, s.ID); err != nil || domain.Status(got.Status) != domain.StatusApproved {
		t.Fatalf("approve again: %+v %v", got, err)
	}
}

// TestF875_ARevokedServerStaysRefusedInEveryMode: modes govern unapproved
// servers; a revoke holds in OFF too, or WATCH to OFF would undo it with no
// second person. A DENIED server stays ENFORCE's business.
//
// Covers: F875
func TestF875_ARevokedServerStaysRefusedInEveryMode(t *testing.T) {
	e := newEnv(t)
	s := e.approved(t, "good", revokedHost, "")
	denied, err := e.svc.Propose(e.alice.ctx, domain.Proposal{
		Name: "bad", Title: "bad", Transport: domain.TransportHTTP, Spec: domain.Spec{Host: "denied.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Deny(e.alice.ctx, denied.ID); err != nil {
		t.Fatal(err)
	}
	e.revokeServer(t, e.alice, s.ID)

	for _, mode := range []domain.Mode{domain.ModeWatch, domain.ModeOff} {
		if _, err := e.svc.SetMode(e.alice.ctx, mode, nil, "set"); err != nil {
			t.Fatal(err)
		}
		if _, err := e.create("again-"+strings.ToLower(string(mode)), "https://"+revokedHost+"/x"); !is(err, app.ErrRevoked) {
			t.Fatalf("%s: %v", mode, err)
		}
		e.mustCreate(t, "denied-"+strings.ToLower(string(mode)), "https://denied.example.test/x")
	}
}

// TestT253_AnUnapprovedServerDoesNotSlipPastTheCatalog: under ENFORCE a
// lookalike host, a sibling path and another port reach no approved server,
// a second entry for a revoked URL does not bring it back, and
// a connection cannot be pointed somewhere else afterwards.
//
// Covers: F874
func TestT253_AnUnapprovedServerDoesNotSlipPastTheCatalog(t *testing.T) {
	e := newEnv(t)
	e.approved(t, "good", revokedHost, "/v1")
	fine := e.mustCreate(t, "fine", "https://"+revokedHost+"/v1/tools")
	e.enforce(t, e.alice)

	for name, url := range map[string]string{
		"lookalike": "https://" + revokedHost + ".evil.example.test/v1",
		"sibling":   "https://" + revokedHost + "/v1x",
		"port":      "https://" + revokedHost + ":8443/v1",
	} {
		if _, err := e.create(name, url); !is(err, app.ErrNotApproved) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	bad := "https://elsewhere.example.test/mcp"
	if _, err := e.conns.Update(e.admin, capp.UpdateInput{ID: fine.ID, Revision: fine.Revision, BaseURL: &bad}); !is(err, app.ErrNotApproved) {
		t.Fatalf("a move: %v", err)
	}

	gone := e.approved(t, "gone", "gone.example.test", "")
	e.revokeServer(t, e.alice, gone.ID)
	e.approved(t, "gone-again", "gone.example.test", "")
	if _, err := e.create("back", "https://gone.example.test/x"); !is(err, app.ErrRevoked) {
		t.Fatalf("a second entry undid a revoke: %v", err)
	}
}

// TestF875_MoreMatchesThanAPlanHolds: past MaxPlanControls the controls fall
// into several plans, all in the one revoke.
//
// Covers: F875
func TestF875_MoreMatchesThanAPlanHolds(t *testing.T) {
	e := newEnv(t)
	s := e.approved(t, "good", revokedHost, "")
	for i := range rapp.MaxPlanControls + 1 {
		e.mustCreate(t, fmt.Sprintf("c%d", i), fmt.Sprintf("https://%s/%d", revokedHost, i))
	}
	r := e.revokeServer(t, e.alice, s.ID)
	if len(r.Controls) != rapp.MaxPlanControls+1 || len(r.Plans) != 2 {
		t.Fatalf("%d controls in %d plans", len(r.Controls), len(r.Plans))
	}
	for _, plan := range r.Plans {
		if _, err := e.decide(t, plan, e.bob.id); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.liveControls(t); n != 0 {
		t.Fatalf("live controls %d", n)
	}
}

// TestF877_AScanOnlyServerIsSaidToBeBeyondReach: a local server a scan saw is
// named with a deny-list hint and nothing happens to it.
//
// Covers: F877
func TestF877_AScanOnlyServerIsSaidToBeBeyondReach(t *testing.T) {
	e := newEnv(t)
	s := e.approved(t, "good", revokedHost, "")
	_, match := e.scanned(t, `{"kind":"mcp_server","name":"laptop","url_host":"`+revokedHost+`"}`)
	e.scanned(t, `{"kind":"mcp_server","name":"unrelated","url_host":"elsewhere.example.test"}`)

	r := e.revokeServer(t, e.alice, s.ID)
	if len(r.Preview.Locals) != 1 || r.Preview.Locals[0].Discovery != match ||
		!strings.Contains(r.Preview.Locals[0].DenyListHint, revokedHost) || !r.Action.IsZero() || len(r.Plans) != 0 {
		t.Fatalf("revoke %+v", r)
	}
	if n := e.int64(t, "SELECT count(*) FROM pc.discoveries WHERE org_id = $1 AND state = 'OPEN'", e.org); n != 2 {
		t.Fatalf("a revoke touched a discovery: %d open", n)
	}
	if got := e.serverStatus(t, s.ID); got != domain.StatusRevoked {
		t.Fatal(got)
	}
}

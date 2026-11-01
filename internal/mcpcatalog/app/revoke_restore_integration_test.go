// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/v2"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	ddomain "github.com/katocxl/pantherclaw/internal/definitions/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/evidence/securityevent"
	"github.com/katocxl/pantherclaw/internal/mcpcatalog/app"
	"github.com/katocxl/pantherclaw/internal/mcpcatalog/domain"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	"github.com/katocxl/pantherclaw/internal/restore"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// chain runs the chainer until every entry of the org is chained. A record it
// cannot project stops here, as it stops the org's chain.
func (e *env) chain(t *testing.T) {
	t.Helper()
	if _, err := ledger.ChainAll(context.Background(), e.pool, e.org, 500); err != nil {
		t.Fatalf("the org's chain stopped: %v", err)
	}
	var left int
	e.d.AdminQueryRow(t, `SELECT count(*) FROM pc.ledger_entries l WHERE org_id = $1
		AND NOT EXISTS (SELECT 1 FROM pc.ledger_chain c WHERE c.org_id = l.org_id AND c.entry_id = l.id)`, []any{e.org}, &left)
	if left != 0 {
		t.Fatalf("%d entries are not chained", left)
	}
}

// shipped reads the org's security log, as a restore is given it.
func (e *env) shipped(t *testing.T) []restore.Event {
	t.Helper()
	var buf bytes.Buffer
	if _, _, err := securityevent.Export(context.Background(), e.pool, e.org, 0, 500, &buf); err != nil {
		t.Fatal(err)
	}
	var out []restore.Event
	for s := bufio.NewScanner(&buf); s.Scan(); {
		var ev restore.Event
		if err := json.Unmarshal(s.Bytes(), &ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

// loseRevocation is a backup taken before the revoke.
func (e *env) loseRevocation(t *testing.T) {
	t.Helper()
	for _, sql := range []string{
		"DELETE FROM pc.restoration_plan_controls WHERE org_id = $1", "DELETE FROM pc.restoration_plans WHERE org_id = $1",
		"DELETE FROM pc.response_paths WHERE org_id = $1", "DELETE FROM pc.containment_controls WHERE org_id = $1",
		"DELETE FROM pc.response_actions WHERE org_id = $1", "UPDATE pc.mcp_servers SET status = 'APPROVED' WHERE org_id = $1",
		"UPDATE pc.package_versions SET state = 'ACTIVE' WHERE org_id = $1",
	} {
		e.d.AdminExec(t, sql, e.org)
	}
}

// TestF875_ARevokeKeepsTheChainAndComesBackFromARestore: a revoke writes one
// response.contain per control, so the chainer projects each and the org's
// chain goes on. A restore from that log brings back every control under the
// one action, the server REVOKED and its versions quarantined, and repeats
// safely (D264).
//
// Covers: F875
func TestF875_ARevokeKeepsTheChainAndComesBackFromARestore(t *testing.T) {
	e := newEnv(t)
	s := e.withPackage(t)
	e.mustCreate(t, "a", "https://"+revokedHost+"/one")
	e.mustCreate(t, "b", "https://"+revokedHost+"/two")
	r := e.revokeServer(t, e.alice, s.ID)
	e.chain(t)

	events := e.shipped(t)
	contained := map[string]bool{}
	revoked := 0
	for _, ev := range events {
		switch ev.Kind {
		case "response.contain":
			if ev.Containment.ActionID != r.Action || ev.Containment.ScopeType != "connection" || ev.Containment.Server != s.ID.String() {
				t.Fatalf("control record %+v", ev.Containment)
			}
			contained[ev.Containment.ControlID.String()] = true
		case "mcp.catalog.server_revoked":
			revoked++
			if ev.Object.Type != "mcp_server" || ev.Object.ID != s.ID.String() {
				t.Fatalf("revoke record %+v", ev.Object)
			}
		}
	}
	if revoked != 1 || len(contained) != len(r.Controls) {
		t.Fatalf("shipped %d revokes and %d controls, want 1 and %d", revoked, len(contained), len(r.Controls))
	}
	for _, c := range r.Controls {
		if !contained[c.String()] {
			t.Fatalf("control %s has no record of its own", c)
		}
	}

	e.loseRevocation(t)
	if got := e.serverStatus(t, s.ID); got != domain.StatusApproved {
		t.Fatalf("before the restore: %s", got)
	}
	operator := evdomain.Actor{Type: "operator", ID: "cli:test"}
	for range 2 {
		if err := restore.NewRegistry().Reapply(context.Background(), e.pool, events, true, operator); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.int64(t, "SELECT count(*) FROM pc.containment_controls WHERE org_id = $1 AND action_id = $2 AND id = ANY($3) AND lifted_at IS NULL",
		e.org, r.Action, r.Controls); n != 2 {
		t.Fatalf("controls back: %d", n)
	}
	if n := e.int64(t, "SELECT count(*) FROM pc.response_actions WHERE org_id = $1 AND id = $2 AND scope_type = 'mcp_server' AND scope_id = $3",
		e.org, r.Action, s.ID.String()); n != 1 {
		t.Fatal("the action does not name the server after a restore")
	}
	if got := e.serverStatus(t, s.ID); got != domain.StatusRevoked {
		t.Fatalf("status after a restore: %s", got)
	}
	if got := e.versionState(t); got != "QUARANTINED" {
		t.Fatalf("version after a restore: %s", got)
	}
	if _, err := e.svc.Approve(e.bob.ctx, s.ID); !is(err, app.ErrRevocationActive) {
		t.Fatalf("approve with a restored control: %v", err)
	}
	e.chain(t)
}

// TestF876_ALiftEndsWhateverStateAConnectionIsIn: one plan holds a connection
// that is active, one quarantined before the revoke and one retired after it.
// The last two make the check not applicable, so neither blocks the rest, and
// a lift leaves each as it was: resuming one stays refused (D265). ACTIVE,
// QUARANTINED and RETIRED are all the states a connection has.
//
// Covers: F876
func TestF876_ALiftEndsWhateverStateAConnectionIsIn(t *testing.T) {
	e := newEnv(t)
	s := e.approved(t, "good", revokedHost, "")
	active := e.mustCreate(t, "active", "https://"+revokedHost+"/a")
	held := e.mustCreate(t, "held", "https://"+revokedHost+"/b")
	gone := e.mustCreate(t, "gone", "https://"+revokedHost+"/c")
	if _, err := e.conns.Quarantine(e.admin, held.ID, "drift"); err != nil {
		t.Fatal(err)
	}
	r := e.revokeServer(t, e.alice, s.ID)
	if len(r.Controls) != 3 || len(r.Plans) != 1 {
		t.Fatalf("revoke %+v", r)
	}
	if err := e.conns.Retire(e.admin, gone.ID); err != nil {
		t.Fatal(err)
	}

	state, err := e.decide(t, r.Plans[0], e.bob.id)
	if err != nil || state != rapp.PlanCompleted {
		t.Fatalf("lift: %s %v", state, err)
	}
	if n := e.liveControls(t); n != 0 {
		t.Fatalf("live controls after the lift: %d", n)
	}
	for id, want := range map[string]string{active.ID.String(): capp.StateActive, held.ID.String(): capp.StateQuarantined, gone.ID.String(): capp.StateRetired} {
		if n := e.int64(t, "SELECT count(*) FROM pc.connections WHERE org_id = $1 AND id = $2::uuid AND state = $3", e.org, id, want); n != 1 {
			t.Fatalf("a lift changed %s from %s", id, want)
		}
	}
	if _, err := e.conns.Restore(e.admin, held.ID); !is(err, app.ErrRevoked) {
		t.Fatalf("resuming under a revoked server: %v", err)
	}
	if got := e.serverStatus(t, s.ID); got != domain.StatusRevoked {
		t.Fatalf("a lift changed the server: %s", got)
	}
}

// TestF875_ARevokeReachesEveryWayToTheEndpoint: a private http connection is
// stopped by a revoke of its host and port, and a new one is refused, though
// the server was approved for https. The explicit http form lets ENFORCE
// approve a private http server, and only that (D266).
//
// Covers: F875
func TestF875_ARevokeReachesEveryWayToTheEndpoint(t *testing.T) {
	e := newEnv(t)
	s := e.approved(t, "private", "10.0.0.5:8080", "")
	over := e.mustCreate(t, "over-http", "http://10.0.0.5:8080/mcp")
	r := e.revokeServer(t, e.alice, s.ID)
	if len(r.Controls) != 1 || len(r.Preview.Connections) != 1 || r.Preview.Connections[0].ID != over.ID {
		t.Fatalf("revoke %+v", r)
	}
	if _, err := e.create("again", "http://10.0.0.5:8080/other"); !is(err, app.ErrRevoked) {
		t.Fatalf("a new connection over http: %v", err)
	}
	if _, err := e.create("again-tls", "https://10.0.0.5:8080/other"); !is(err, app.ErrRevoked) {
		t.Fatalf("a new connection over https: %v", err)
	}

	e.approved(t, "lab", "http://10.0.0.6:8080", "")
	e.enforce(t, e.alice)
	e.mustCreate(t, "lab", "http://10.0.0.6:8080/mcp")
	if _, err := e.create("lab-tls", "https://10.0.0.6:8080/mcp"); !is(err, app.ErrNotApproved) {
		t.Fatalf("https under the http form: %v", err)
	}
}

// TestF875_ARevokeStopsVersionsNotYetActive: a REVIEWED version is quarantined
// with the rest, and no version of a revoked server's package activates, until
// the server is trusted again (D267).
//
// Covers: F875
func TestF875_ARevokeStopsVersionsNotYetActive(t *testing.T) {
	e := newEnv(t)
	s := e.withPackage(t)
	e.exec(t, "UPDATE pc.package_versions SET state = 'REVIEWED' WHERE org_id = $1", e.org)
	e.revokeServer(t, e.alice, s.ID)
	if got := e.versionState(t); got != "QUARANTINED" {
		t.Fatalf("a reviewed version: %s", got)
	}

	store := &defspg.Store{Pool: e.pool}
	admin := &defsapp.Admin{Importer: &defsapp.Importer{Repo: store}, Reads: store, Authz: allowAll{}, Pool: e.pool, Catalog: app.Gate{}}
	e.exec(t, "UPDATE pc.package_versions SET state = 'REVIEWED' WHERE org_id = $1", e.org)
	if _, err := admin.Transition(e.alice.ctx, mcpPackage, "1.0.0", ddomain.StateActive); !is(err, app.ErrRevoked) {
		t.Fatalf("activating a revoked server's package: %v", err)
	}
	if got := e.versionState(t); got != "REVIEWED" {
		t.Fatalf("after the refusal: %s", got)
	}
	if _, err := e.svc.Approve(e.bob.ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Transition(e.alice.ctx, mcpPackage, "1.0.0", ddomain.StateActive); err != nil {
		t.Fatalf("once trusted again: %v", err)
	}
}

type allowAll struct{}

func (allowAll) Require(tapp.Caller, td.Permission, td.Path) error { return nil }

// TestF875_ADowngradedOrgCanAlwaysRevoke: a revoke and its preview need no
// edition, since stopping a server is Safety class (D268).
//
// Covers: F875
func TestF875_ADowngradedOrgCanAlwaysRevoke(t *testing.T) {
	e := newEnv(t)
	s := e.approved(t, "good", revokedHost, "")
	e.mustCreate(t, "a", "https://"+revokedHost+"/x")
	e.edition.e = billing.Community
	if r := e.revokeServer(t, e.alice, s.ID); len(r.Controls) != 1 {
		t.Fatalf("revoke %+v", r)
	}
}

// TestHR586_ALapsedOrgCanStillLeaveEnforce: filing the weakening and the
// second person's confirm both work without the edition (D261). The confirm is
// POST /changes/{id}/confirm, outside the procedure classes, which reaches
// ApplyMode through the Gate.
//
// Covers: F874
func TestHR586_ALapsedOrgCanStillLeaveEnforce(t *testing.T) {
	e := newEnv(t)
	e.approved(t, "good", revokedHost, "")
	e.enforce(t, e.alice)
	e.edition.e = billing.Community
	r, err := e.svc.SetMode(e.alice.ctx, domain.ModeOff, nil, "the plan lapsed")
	if err != nil || r.Held == nil {
		t.Fatalf("filing: %+v %v", r, err)
	}
	if err := e.confirm(r.Held, e.bob.id); err != nil {
		t.Fatalf("confirming on a lapsed plan: %v", err)
	}
	e.edition.e = billing.Team
	if m := e.mode(t); m != domain.ModeOff {
		t.Fatalf("mode %s", m)
	}
}

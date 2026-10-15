// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

// world is one org with a gateway serving one connection, an agent with an
// active run under a grant of alice's, and the agent's coverage of one
// operation on the connection.
type world struct {
	t                                *testing.T
	d                                *dbtest.DB
	pool                             *db.Pool
	c                                *rapp.Containment
	org                              ids.OrgID
	alice, gateway, conn, agent, run ids.UUID
	grant                            ids.UUID
}

func newWorld(t *testing.T, coverage string) *world {
	t.Helper()
	d := dbtest.New(t)
	w := &world{
		t: t, d: d, pool: d.AppPool(t), org: ids.New[ids.Org](), alice: ids.NewV7(), gateway: ids.NewV7(), conn: ids.NewV7(),
		agent: ids.NewV7(), run: ids.NewV7(), grant: ids.NewV7(),
	}
	w.c = &rapp.Containment{Pool: w.pool, Raiser: &alerts.Raiser{}, Failures: &failures.Sink{}}
	env := ids.NewV7()
	w.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", w.org)
	w.exec("INSERT INTO pc.org_containment (org_id) VALUES ($1)", w.org)
	w.exec(`INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')`, w.org, w.alice)
	w.exec("INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, 'dev', 'Dev', 'DEVELOPMENT')", w.org, env)
	w.exec("INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", w.org, w.gateway)
	w.exec(`INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode, created_by, updated_by)
		VALUES ($1, $2, 'payments', 'http', $3, 'mock-payments', 'https://payments.test', 'pantherclaw_held', 'enforce', 'test', 'test')`,
		w.org, w.conn, w.gateway)
	w.exec("INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'coder', 'DISCOVERED', 'test')", w.org, w.agent)
	w.exec(`INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision, grantor_kind,
		grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'test')`, w.org, w.grant, w.agent, w.alice, env)
	w.exec("INSERT INTO pc.grant_lineage (org_id, grant_id, ancestor_id, distance) VALUES ($1, $2, $2, 0)", w.org, w.grant)
	w.exec(`INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at, grant_id)
		VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '8 hours', $6)`, w.org, w.run, w.agent, env, w.alice, w.grant)
	if coverage != "" {
		entry := ids.NewV7()
		w.exec(`INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body) VALUES ($1, $2, 'coverage.snapshot', 'system', 'test', '\x7b7d')`,
			w.org, entry)
		w.exec(`INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons, body, body_sha256, ledger_entry_id)
			VALUES ($1, $2, $3, $4, 'payments.refund.create', $5, '{}', '{}', decode(repeat('00', 32), 'hex'), $6)`,
			w.org, ids.NewV7(), w.agent, w.conn, coverage, entry)
	}
	return w
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	w.d.AdminExec(w.t, sql, args...)
}

func (w *world) tx(fn func(ctx context.Context, tx db.TenantTx) error) error {
	return w.pool.InTenantTx(context.Background(), w.org, fn)
}

func (w *world) contain(r reflexdomain.ContainRequest) (reflexdomain.ContainResult, error) {
	r.Org = w.org
	if r.Actor == (reflexdomain.Subject{}) {
		r.Actor = reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: w.alice.String()}
	}
	if r.Reason == "" {
		r.Reason = "suspicious refunds"
	}
	var out reflexdomain.ContainResult
	err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = w.c.Contain(ctx, tx.Pgx(), r)
		return err
	})
	return out, err
}

func (w *world) action(id ids.UUID) dbq.PcResponseAction {
	w.t.Helper()
	var a dbq.PcResponseAction
	if err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		a, err = dbq.New(tx).GetResponseAction(ctx, w.org, id)
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
	return a
}

func (w *world) advance(id ids.UUID) dbq.PcResponseAction {
	w.t.Helper()
	if err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
		a, err := dbq.New(tx).GetResponseAction(ctx, w.org, id)
		if err != nil {
			return err
		}
		_, err = w.c.Advance(ctx, tx, a)
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
	return w.action(id)
}

func (w *world) deliver(epoch int64) {
	w.t.Helper()
	if err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).RecordEpochDelivery(ctx, w.org, w.gateway, epoch)
	}); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) count(sql string, args ...any) int {
	w.t.Helper()
	var n int
	w.d.AdminQueryRow(w.t, sql, args, &n)
	return n
}

// TestHR248_ContainerAddsAControlTheAuthorityEnforces: a narrow DENY_ALL on
// a run commits without a preview, raises the epoch, is what the Authority
// reads in its decision snapshot, and is recorded in the ledger and audit.
func TestHR248_ContainerAddsAControlTheAuthorityEnforces(t *testing.T) {
	w := newWorld(t, "PARTIAL")
	before, err := (&pgauthority.Reader{Pool: w.pool}).Containment(context.Background(), w.org)
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.contain(reflexdomain.ContainRequest{
		Scope: reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: w.run.String()}, Control: reflexdomain.ControlDenyAll,
	})
	if err != nil {
		t.Fatal(err)
	}
	after, err := (&pgauthority.Reader{Pool: w.pool}).Containment(context.Background(), w.org)
	if err != nil {
		t.Fatal(err)
	}
	if after.Epoch != before.Epoch+1 || len(after.Controls) != 1 || after.Controls[0].ScopeID != w.run.String() ||
		after.Controls[0].Control != rdomain.DenyAll {
		t.Fatalf("authority containment after: %+v (epoch before %d)", after, before.Epoch)
	}
	a := w.action(res.ActionID)
	if a.Status != string(rdomain.StatusRequested) || a.Epoch.Int64 != after.Epoch || a.Source != rdomain.SourcePerson {
		t.Fatalf("action %+v", a)
	}
	if n := w.count("SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind IN ('response.action', 'audit.response.contain')", w.org); n != 2 {
		t.Fatalf("%d ledger entries, want the action and its audit", n)
	}
	if _, err := w.contain(reflexdomain.ContainRequest{
		Scope: reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: ids.NewV7().String()}, Control: reflexdomain.ControlDenyAll,
	}); !errors.Is(err, rapp.ErrScopeNotFound) {
		t.Fatalf("a run of no one: %v", err)
	}
}

// TestHR249_ConfirmedOnlyWhenEveryMaterialPathIs: an action waits
// (REQUESTED) until its gateway is sent its epoch, then a route the gateway
// enforces confirms with it and the action is CONFIRMED with new access
// stopped. A bypass route (OBSERVE_ONLY) stays unresolved, so the same
// control on such an agent is PARTIAL however its gateway confirms; new
// access through the gateway is reported stopped on its own (F561).
func TestHR249_ConfirmedOnlyWhenEveryMaterialPathIs(t *testing.T) {
	w := newWorld(t, "PARTIAL")
	res, err := w.contain(reflexdomain.ContainRequest{
		Scope: reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: w.run.String()}, Control: reflexdomain.ControlDenyAll,
	})
	if err != nil {
		t.Fatal(err)
	}
	a := w.advance(res.ActionID)
	if a.Status != string(rdomain.StatusRequested) || a.FutureConfirmed {
		t.Fatalf("before delivery: %s future=%v", a.Status, a.FutureConfirmed)
	}
	w.deliver(a.Epoch.Int64 - 1)
	if a = w.advance(res.ActionID); a.Status != string(rdomain.StatusRequested) {
		t.Fatalf("an older epoch confirmed the gateway: %s", a.Status)
	}
	w.deliver(a.Epoch.Int64)
	if a = w.advance(res.ActionID); a.Status != string(rdomain.StatusConfirmed) || !a.FutureConfirmed || a.SettledAt == nil {
		t.Fatalf("after delivery: %s future=%v", a.Status, a.FutureConfirmed)
	}

	b := newWorld(t, "OBSERVE_ONLY")
	res, err = b.contain(reflexdomain.ContainRequest{
		Scope: reflexdomain.Subject{Type: reflexdomain.SubjectAgent, ID: b.agent.String()}, Control: reflexdomain.ControlDenyAll,
	})
	if err != nil {
		t.Fatal(err)
	}
	a = b.action(res.ActionID)
	if a.Status != string(rdomain.StatusPartial) {
		t.Fatalf("a bypass route: %s", a.Status)
	}
	b.deliver(a.Epoch.Int64)
	if a = b.advance(res.ActionID); a.Status != string(rdomain.StatusPartial) || !a.FutureConfirmed {
		t.Fatalf("a bypass route after delivery: %s future=%v", a.Status, a.FutureConfirmed)
	}
}

// TestHR249_FailedContainmentRaisesASignal: a gateway path not confirmed
// within its deadline fails the action, which raises a response alert and
// an owned failure.
func TestHR249_FailedContainmentRaisesASignal(t *testing.T) {
	w := newWorld(t, "PARTIAL")
	res, err := w.contain(reflexdomain.ContainRequest{
		Scope: reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: w.run.String()}, Control: reflexdomain.ControlDenyAll,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.exec("UPDATE pc.response_actions SET requested_at = now() - interval '6 minutes' WHERE org_id = $1 AND id = $2", w.org, res.ActionID)
	if a := w.advance(res.ActionID); a.Status != string(rdomain.StatusFailed) {
		t.Fatalf("status %s, want FAILED", a.Status)
	}
	if n := w.count("SELECT count(*) FROM pc.alerts WHERE org_id = $1 AND source = 'response'", w.org); n != 1 {
		t.Fatalf("%d response alerts", n)
	}
	if n := w.count("SELECT count(*) FROM pc.operational_failures WHERE org_id = $1 AND kind = 'containment_failed'", w.org); n != 1 {
		t.Fatalf("%d owned failures", n)
	}
}

// TestHR252_WiderContainmentNeedsTheCurrentPreview: a control wider than one
// run or agent is refused without its preview's digest, or with a digest
// the scope has since outgrown, and committed with the current one; the
// identity playbook needs none but is limited to a person and the grants
// they issued (D50), and a SOAR request never comes through the port. An
// idempotency key returns its first
// result and refuses a different request.
func TestHR252_WiderContainmentNeedsTheCurrentPreview(t *testing.T) {
	w := newWorld(t, "PARTIAL")
	wide := reflexdomain.ContainRequest{
		Scope: reflexdomain.Subject{Type: reflexdomain.SubjectGrant, ID: w.grant.String()}, Control: reflexdomain.ControlDenyAll,
	}
	if _, err := w.contain(wide); !errors.Is(err, rapp.ErrPreviewStale) {
		t.Fatalf("without a preview: %v", err)
	}
	var p rapp.Preview
	if err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		p, err = w.c.PreviewIn(ctx, tx, rdomain.Control{ScopeType: rdomain.ScopeGrant, ScopeID: w.grant.String(), Control: rdomain.DenyAll, Reason: "x"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(p.Runs) != 1 || p.Runs[0] != w.run || len(p.Gateways) != 1 {
		t.Fatalf("preview %+v", p)
	}
	// Another run under the grant starts: the preview is stale.
	w.exec(`INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at, grant_id)
		SELECT org_id, $2, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at, grant_id
		FROM pc.runs WHERE org_id = $1 AND id = $3`, w.org, ids.NewV7(), w.run)
	wide.PreviewDigest = p.Digest
	if _, err := w.contain(wide); !errors.Is(err, rapp.ErrPreviewStale) {
		t.Fatalf("with a stale preview: %v", err)
	}
	if err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		p, err = w.c.PreviewIn(ctx, tx, rdomain.Control{ScopeType: rdomain.ScopeGrant, ScopeID: w.grant.String(), Control: rdomain.DenyAll, Reason: "x"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	wide.PreviewDigest = p.Digest
	if _, err := w.contain(wide); err != nil {
		t.Fatalf("with the current preview: %v", err)
	}

	playbook := func(scope reflexdomain.Subject, control string) (reflexdomain.ContainResult, error) {
		return w.contain(reflexdomain.ContainRequest{Scope: scope, Control: control, Actor: rapp.PlaybookActor})
	}
	grant := reflexdomain.Subject{Type: reflexdomain.SubjectGrant, ID: w.grant.String()}
	alice := reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: w.alice.String()}
	// D50: the playbook contains a person, then the grants they issued;
	// nothing else, and no grant before its issuer is contained.
	for _, c := range []struct {
		scope   reflexdomain.Subject
		control string
	}{
		{grant, reflexdomain.ControlDenyAll},
		{reflexdomain.Subject{Type: reflexdomain.SubjectAgent, ID: w.agent.String()}, reflexdomain.ControlDenyAll},
		{alice, reflexdomain.ControlHoldWrites},
		{reflexdomain.Subject{Type: reflexdomain.SubjectConnection, ID: w.conn.String()}, reflexdomain.ControlDenyAll},
	} {
		if _, err := playbook(c.scope, c.control); !errors.Is(err, rapp.ErrPlaybookScope) {
			t.Errorf("the playbook on %s %s: %v", c.scope.Type, c.control, err)
		}
	}
	byPlaybook, err := playbook(alice, reflexdomain.ControlDenyAll)
	if err != nil {
		t.Fatalf("the identity playbook: %v", err)
	}
	if _, err := playbook(grant, reflexdomain.ControlDenyAll); err != nil {
		t.Fatalf("the playbook on a grant its person issued: %v", err)
	}
	// No digest was supplied: the server recorded the preview it computed.
	if a := w.action(byPlaybook.ActionID); a.Source != rdomain.SourcePlaybook || len(a.PreviewDigest) != 32 || len(a.PreviewSummary) < 10 {
		t.Fatalf("playbook action: %s %x %s", a.Source, a.PreviewDigest, a.PreviewSummary)
	}
	// A SOAR integration never contains through the port.
	if _, err := w.contain(reflexdomain.ContainRequest{
		Scope: reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: w.run.String()}, Control: reflexdomain.ControlDenyAll,
		Actor: reflexdomain.Subject{Type: reflexdomain.SubjectServiceAccount, ID: ids.NewV7().String()},
	}); !errors.Is(err, rapp.ErrSOARPort) {
		t.Fatalf("a service account through the port: %v", err)
	}

	keyed := reflexdomain.ContainRequest{
		Scope: reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: w.run.String()}, Control: reflexdomain.ControlHoldWrites,
		Idempotency: "soar-1",
	}
	first, err := w.contain(keyed)
	if err != nil {
		t.Fatal(err)
	}
	again, err := w.contain(keyed)
	if err != nil || again.ActionID != first.ActionID {
		t.Fatalf("repeat: %v %v / %v", again, err, first)
	}
	keyed.Control = reflexdomain.ControlDenyAll
	if _, err := w.contain(keyed); !errors.Is(err, rapp.ErrIdempotency) {
		t.Fatalf("a different request under the key: %v", err)
	}
}

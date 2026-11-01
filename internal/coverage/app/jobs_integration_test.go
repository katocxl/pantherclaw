// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func (f *fixture) reassessOrg(t *testing.T) app.Reassessed {
	t.Helper()
	r, err := f.svc.ReassessOrg(context.Background(), f.org)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *fixture) pending(t *testing.T) int {
	t.Helper()
	var n int
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).PendingCoverageInvalidations(ctx, f.org, 100)
		n = len(rows)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestHR211_TheReassessJobFollowsEveryChange: the job reads new traffic,
// reassesses the scopes of each pending invalidation, recording the change
// as the snapshot's cause, marks them reassessed, and reassesses a current
// ENFORCED snapshot that lapsed.
func TestHR211_TheReassessJobFollowsEveryChange(t *testing.T) {
	f := newFixture(t)
	const op = "payments.refund.create"
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7, 'http',
		'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), op, f.conn)
	if _, err := f.record(t, f.closure(probes(false), f.dbNow(t))); err != nil {
		t.Fatal(err)
	}
	if r := f.reassessOrg(t); r.Scopes != 1 || r.Snapshots != 1 {
		t.Fatalf("first run %+v", r)
	}
	row, _, _ := f.current(t, op)
	if row.State != "ENFORCED" {
		t.Fatalf("state %s", row.State)
	}
	if n := f.pending(t); n != 0 {
		t.Fatalf("%d invalidations pending after the run", n)
	}
	var observed time.Time
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		c, err := dbq.New(tx).GetCoverageClosure(ctx, f.org, *row.ClosureID)
		observed = c.ObservedAt
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if e := f.graphEdge(t); e.ValidatedAt == nil || !e.ValidatedAt.Equal(observed) || e.InvalidatedBy != "" {
		t.Fatalf("a validated scope, want validated at %v: %+v", observed, e)
	}
	f.exec(t, `UPDATE pc.connections SET access_mode = 'agent_held' WHERE id = $1`, f.conn)
	if r := f.reassessOrg(t); r.Snapshots != 1 {
		t.Fatalf("after a connection change %+v", r)
	}
	row, s, _ := f.current(t, op)
	if row.State != "PARTIAL" || row.InvalidationID == nil || s.Cause != row.InvalidationID.String() ||
		row.LastValidID == nil {
		t.Fatalf("after a connection change: %s cause %v last valid %v", row.State, row.InvalidationID, row.LastValidID)
	}
	// The reason is a reason code and the invalidation has its own field,
	// never one in the other's place (D36).
	if e := f.graphEdge(t); len(s.Reasons) == 0 || e.Reason != s.Reasons[0] || e.InvalidatedBy != row.InvalidationID.String() {
		t.Fatalf("reasons %v, invalidation %v: %+v", s.Reasons, row.InvalidationID, e)
	}
	if n := f.pending(t); n != 0 {
		t.Fatalf("%d invalidations pending after the run", n)
	}
	// A current ENFORCED snapshot past its expiry is reassessed.
	closure := f.closureID(t)
	f.exec(t, `INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons, closure_id,
		body, body_sha256, ledger_entry_id, computed_at, expires_at)
		SELECT org_id, $2, agent_id, connection_id, operation, 'ENFORCED', '{}', $3, body, body_sha256, $4,
		       now() - interval '2 days', now() - interval '1 day'
		FROM pc.coverage_snapshots WHERE org_id = $1 ORDER BY id DESC LIMIT 1`, f.org, ids.NewV7(), closure, f.ledgerEntry(t))
	if n := f.staleMetric(t); n != 1 {
		t.Fatalf("the staleness metric reads %d with one lapsed record", n)
	}
	if r := f.reassessOrg(t); r.Scopes != 1 || r.Snapshots != 1 {
		t.Fatalf("a lapsed ENFORCED snapshot: %+v", r)
	}
	if row, _, _ := f.current(t, op); row.State != "PARTIAL" {
		t.Fatalf("after the lapse: %s", row.State)
	}
	if n := f.staleMetric(t); n != 0 {
		t.Fatalf("the staleness metric reads %d after reassessment", n)
	}
	// A change the record did not see lapses it as well (L7).
	f.exec(t, `INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id) VALUES ($1, $2, 'connection', $3)`,
		f.org, ids.NewV7(), f.conn)
	if n := f.staleMetric(t); n != 1 {
		t.Fatalf("the staleness metric reads %d with one record lapsed on an unseen change", n)
	}
	if r := f.reassessOrg(t); r.Snapshots != 1 {
		t.Fatalf("after an unseen change %+v", r)
	}
	if n := f.staleMetric(t); n != 0 {
		t.Fatalf("the staleness metric reads %d after the change was seen", n)
	}
}

// graphEdge is the edge into the agent's first scope.
func (f *fixture) graphEdge(t *testing.T) app.GraphEdge {
	t.Helper()
	f.svc.Ents = edition(billing.Team)
	g, err := f.svc.GetCoverageGraph(f.as(td.RoleAuditor), f.agent, app.GraphFilter{Connection: &f.conn})
	if err != nil || len(g.Edges) == 0 {
		t.Fatalf("graph %+v (%v)", g, err)
	}
	return g.Edges[0]
}

// staleMetric is the staleness metric's source (F301).
func (f *fixture) staleMetric(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		n, err = dbq.New(tx).MetricCoverageStale(ctx, f.org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *fixture) closureID(t *testing.T) ids.UUID {
	t.Helper()
	var id ids.UUID
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT id FROM pc.coverage_closures ORDER BY id DESC LIMIT 1").Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fixture) ledgerEntry(t *testing.T) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	f.exec(t, `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body)
		VALUES ($1, $2, 'coverage.test', 'test', 'test', '\x7b7d')`, f.org, id)
	return id
}

// TestHR211_APoisonScopeIsSkippedAndItsChangesStayPending: a scope whose
// evidence cannot be read (its package does not decode) is rolled back,
// counted and skipped, the org's other scopes are still recorded, and only
// the invalidations of the scopes that were reassessed are marked and
// entered in the ledger.
func TestHR211_APoisonScopeIsSkippedAndItsChangesStayPending(t *testing.T) {
	f := newFixture(t)
	const op = "payments.refund.create"
	broken, pkg, version := ids.NewV7(), ids.NewV7(), ids.NewV7()
	f.exec(t, "INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, 'pc.broken')", f.org, pkg)
	f.exec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
		VALUES ($1, $2, $3, '1.0.0', $4, '\x7b7d', 'ACTIVE')`, f.org, version, pkg, digest)
	f.exec(t, `INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest) VALUES ($1, $2, $3, '1.0.0', $4)`,
		f.org, pkg, version, digest)
	f.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode,
		created_by, updated_by) VALUES ($1, $2, 'broken', 'http', $3, 'pc.broken', 'https://api.broken.example',
		'pantherclaw_held', 'enforce', 'test', 'test')`, f.org, broken, f.gateway)
	for _, conn := range []ids.UUID{f.conn, broken} {
		f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
			gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7, 'http',
			'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), op, conn)
	}
	f.exec(t, `INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id) VALUES ($1, $2, 'connection', $3)`,
		f.org, ids.NewV7(), broken)
	r := f.reassessOrg(t)
	if r.Skipped != 1 || r.Snapshots != 1 {
		t.Fatalf("run %+v, want the broken scope skipped and the other recorded", r)
	}
	if row, _, _ := f.current(t, op); row.State != "PARTIAL" {
		t.Fatalf("the healthy scope: %s", row.State)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.coverage_invalidations WHERE reassessed_at IS NULL AND connection_id = $1
		AND kind = 'connection'`, broken); n != 1 {
		t.Fatalf("%d pending changes of the broken scope, want its change kept", n)
	}
	marked := f.count(t, "SELECT count(*) FROM pc.coverage_invalidations WHERE reassessed_at IS NOT NULL")
	if n := f.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'coverage.invalidation'"); marked == 0 || n != marked {
		t.Fatalf("%d invalidation entries for %d marked changes", n, marked)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.coverage_invalidations i JOIN pc.ledger_entries e ON e.org_id = i.org_id
		AND e.id = i.ledger_entry_id AND e.kind = 'coverage.invalidation'`); n != marked {
		t.Fatalf("%d marked changes name their entry, want %d", n, marked)
	}
}

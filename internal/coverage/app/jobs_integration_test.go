// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
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
	if row, _, _ := f.current(t, op); row.State != "ENFORCED" {
		t.Fatalf("state %s", row.State)
	}
	if n := f.pending(t); n != 0 {
		t.Fatalf("%d invalidations pending after the run", n)
	}
	f.exec(t, `UPDATE pc.connections SET access_mode = 'agent_held' WHERE id = $1`, f.conn)
	if r := f.reassessOrg(t); r.Snapshots != 1 {
		t.Fatalf("after a connection change %+v", r)
	}
	row, s, _ := f.current(t, op)
	if row.State != "PARTIAL" || row.InvalidationID == nil || s.Cause == nil || *s.Cause != *row.InvalidationID ||
		row.LastValidID == nil {
		t.Fatalf("after a connection change: %s cause %v last valid %v", row.State, row.InvalidationID, row.LastValidID)
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
	if r := f.reassessOrg(t); r.Scopes != 1 || r.Snapshots != 1 {
		t.Fatalf("a lapsed ENFORCED snapshot: %+v", r)
	}
	if row, _, _ := f.current(t, op); row.State != "PARTIAL" {
		t.Fatalf("after the lapse: %s", row.State)
	}
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

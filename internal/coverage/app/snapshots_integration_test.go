// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// current returns the scope's current snapshot and its ledger body.
func (f *fixture) current(t *testing.T, op string) (dbq.PcCoverageSnapshot, app.Snapshot, []byte) {
	t.Helper()
	var row dbq.PcCoverageSnapshot
	var body []byte
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		row, err = dbq.New(tx).CurrentCoverageSnapshot(ctx, dbq.CurrentCoverageSnapshotParams{
			OrgID: f.org, AgentID: f.agent, ConnectionID: f.conn, Operation: op,
		})
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT body FROM pc.ledger_entries WHERE id = $1", row.LedgerEntryID).Scan(&body)
	})
	if err != nil {
		t.Fatal(err)
	}
	var s app.Snapshot
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatal(err)
	}
	return row, s, body
}

func (f *fixture) reassess(t *testing.T) app.Reassessed {
	t.Helper()
	r, err := f.svc.Reassess(f.as(td.RoleSecurityAdmin), f.conn, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestHR211_ReassessmentRecordsChangesAndKeepsTheLastValidRecord: traffic
// alone gives PARTIAL, a passing closure ENFORCED with its expiry, and a
// route switched to monitor mode drops the scope at once, keeping the
// ENFORCED snapshot as its last valid record. Each snapshot is a ledger
// entry whose digest the row keeps; an unchanged scope records nothing.
func TestHR211_ReassessmentRecordsChangesAndKeepsTheLastValidRecord(t *testing.T) {
	f := newFixture(t)
	const op = "payments.refund.create"
	if r := f.reassess(t); r.Scopes != 0 {
		t.Fatalf("a connection without traffic has scopes: %+v", r)
	}
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7, 'http',
		'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), op, f.conn)
	if r := f.reassess(t); r.Scopes != 1 || r.Snapshots != 1 {
		t.Fatalf("first reassessment %+v", r)
	}
	row, s, body := f.current(t, op)
	digest := sha256.Sum256(body)
	if row.State != "PARTIAL" || s.ID != row.ID || !slices.Equal(row.BodySha256, digest[:]) ||
		!slices.Contains(s.Reasons, domain.ReasonNoClosure) {
		t.Fatalf("traffic only: %s %v (body id %v, row %v)", row.State, s.Reasons, s.ID, row.ID)
	}
	if r := f.reassess(t); r.Snapshots != 0 {
		t.Fatalf("an unchanged scope recorded %+v", r)
	}
	if _, err := f.record(t, f.closure(probes(false), f.dbNow(t))); err != nil {
		t.Fatal(err)
	}
	f.reassess(t)
	enforced, s, _ := f.current(t, op)
	if enforced.State != "ENFORCED" || enforced.ExpiresAt == nil || enforced.ClosureID == nil || s.ExpiresAt == "" {
		t.Fatalf("with a passing closure: %s %v", enforced.State, s.Reasons)
	}
	f.exec(t, `INSERT INTO pc.connection_routes (org_id, connection_id, route, mode, changed_by)
		VALUES ($1, $2, 'payments-refund', 'monitor', 'test')`, f.org, f.conn)
	f.reassess(t)
	row, s, _ = f.current(t, op)
	if row.State != "OBSERVE_ONLY" || row.LastValidID == nil || *row.LastValidID != enforced.ID || s.LastValid == nil {
		t.Fatalf("after monitor mode: %s, last valid %v", row.State, row.LastValidID)
	}
}

// TestIntReassessIsForPeopleWithCoverageManage: a viewer cannot reassess.
func TestIntReassessIsForPeopleWithCoverageManage(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Reassess(f.as(td.RoleViewer), f.conn, nil); !errors.Is(err, td.ErrPermissionDenied(td.PermCoverageManage)) {
		t.Fatalf("a viewer reassessed: %v", err)
	}
	if _, err := f.svc.Reassess(f.as(td.RoleSecurityAdmin), ids.NewV7(), nil); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("an unknown connection: %v", err)
	}
}

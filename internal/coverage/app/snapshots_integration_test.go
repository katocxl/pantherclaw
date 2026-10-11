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
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// current returns the scope's current snapshot, its full record and its
// ledger body.
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
	if err := json.Unmarshal(row.Body, &s); err != nil {
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
	var entry app.Entry
	if err := json.Unmarshal(body, &entry); err != nil {
		t.Fatal(err)
	}
	if row.State != "PARTIAL" || s.ID != row.ID || !slices.Equal(row.BodySha256, digest[:]) ||
		!slices.Contains(s.Reasons, domain.ReasonNoClosure) {
		t.Fatalf("traffic only: %s %v (body id %v, row %v)", row.State, s.Reasons, s.ID, row.ID)
	}
	if entry.Snapshot != row.ID || entry.State != "PARTIAL" || entry.Scope.Operation != op || entry.Scope.Agent != f.agent ||
		!strings.HasPrefix(entry.RoutesDigest, "sha256:") || entry.Exclusions == nil {
		t.Fatalf("ledger entry %+v", entry)
	}
	if r := f.reassess(t); r.Snapshots != 0 {
		t.Fatalf("an unchanged scope recorded %+v", r)
	}
	if _, err := f.record(t, f.closure(probes(false), f.dbNow(t))); err != nil {
		t.Fatal(err)
	}
	// Recording the closure reassessed its scope at once.
	enforced, s, _ := f.current(t, op)
	if enforced.State != "ENFORCED" || enforced.ExpiresAt == nil || enforced.ClosureID == nil || s.ExpiresAt == "" {
		t.Fatalf("with a passing closure: %s %v", enforced.State, s.Reasons)
	}
	if r := f.reassess(t); r.Snapshots != 0 {
		t.Fatalf("a reassessment after the closure recorded %+v", r)
	}
	f.exec(t, `INSERT INTO pc.connection_routes (org_id, connection_id, route, mode, changed_by)
		VALUES ($1, $2, 'payments-refund', 'monitor', 'test')`, f.org, f.conn)
	f.reassess(t)
	row, s, _ = f.current(t, op)
	if row.State != "OBSERVE_ONLY" || row.LastValidID == nil || *row.LastValidID != enforced.ID || s.LastValid == nil {
		t.Fatalf("after monitor mode: %s, last valid %v", row.State, row.LastValidID)
	}
}

// TestIntReassessNeedsCoverageReassess: a viewer or a developer cannot
// reassess; an agent owner can, for an agent or the whole connection.
func TestIntReassessNeedsCoverageReassess(t *testing.T) {
	f := newFixture(t)
	for _, r := range []td.RoleName{td.RoleViewer, td.RoleDeveloper} {
		if _, err := f.svc.Reassess(f.as(r), f.conn, nil); !errors.Is(err, td.ErrPermissionDenied(td.PermCoverageReassess)) {
			t.Fatalf("%s reassessed: %v", r, err)
		}
	}
	if _, err := f.svc.Reassess(f.as(td.RoleAgentOwner), f.conn, &f.agent); err != nil {
		t.Fatalf("an agent owner: %v", err)
	}
	if _, err := f.svc.Reassess(f.as(td.RoleSecurityAdmin), ids.NewV7(), nil); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("an unknown connection: %v", err)
	}
}

// TestHR211_AnInvalidationIsNotLostBehindExclusions: the changes since a
// closure's session that make it stale are read past any number of
// exclusions and route changes, which never make it stale.
func TestHR211_AnInvalidationIsNotLostBehindExclusions(t *testing.T) {
	f := newFixture(t)
	const op = "payments.refund.create"
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7, 'http',
		'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), op, f.conn)
	if _, err := f.record(t, f.closure(probes(false), f.dbNow(t))); err != nil {
		t.Fatal(err)
	}
	f.reassess(t)
	if row, _, _ := f.current(t, op); row.State != "ENFORCED" {
		t.Fatalf("baseline %s", row.State)
	}
	for range 65 {
		f.exec(t, `INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id) VALUES ($1, $2, 'exclusion', $3)`,
			f.org, ids.NewV7(), f.conn)
	}
	f.exec(t, `INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id) VALUES ($1, $2, 'credential', $3)`,
		f.org, ids.NewV7(), f.conn)
	f.reassess(t)
	if row, s, _ := f.current(t, op); row.State == "ENFORCED" || !slices.Contains(s.Reasons, "invalidated:credential") {
		t.Fatalf("after 65 exclusions and a credential change: %s %v", row.State, s.Reasons)
	}
}

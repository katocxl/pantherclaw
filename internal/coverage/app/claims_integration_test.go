// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR217_AClaimIsTheCurrentSnapshotAsItReadsAtDecisionTime: no claim for
// a scope never assessed; an ENFORCED claim names the current snapshot, its
// state and its exclusions; after its expiry or a change it did not see,
// the claim on the same snapshot is lapsed, says why and is the scope
// recomputed then, capped at PARTIAL.
func TestHR217_AClaimIsTheCurrentSnapshotAsItReadsAtDecisionTime(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	sc := domain.Scope{Agent: f.agent, Connection: f.conn, Operation: "payments.refund.create"}
	if c, err := f.svc.ClaimAt(ctx, f.org, sc, time.Now()); err != nil || c != nil {
		t.Fatalf("a scope never assessed: %+v (%v)", c, err)
	}
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7, 'http',
		'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), sc.Operation, f.conn)
	if _, err := f.record(t, f.closure(probes(false), f.dbNow(t))); err != nil {
		t.Fatal(err)
	}
	f.reassessOrg(t)
	row, _, _ := f.current(t, sc.Operation)
	now := time.Now()
	c, err := f.svc.ClaimAt(ctx, f.org, sc, now)
	if err != nil || c == nil || c.State != domain.Enforced || c.Snapshot != row.ID || c.SnapshotState != domain.Enforced ||
		c.Lapsed || c.Reason != "" || len(c.Exclusions) != 0 || c.ExpiresAt == nil {
		t.Fatalf("an ENFORCED scope: %+v (%v)", c, err)
	}
	if c, _ := f.svc.ClaimAt(ctx, f.org, sc, row.ExpiresAt.Add(time.Second)); c == nil || c.State != domain.Partial || c.Snapshot != row.ID ||
		!c.Lapsed || c.Reason != domain.LapseExpired || c.SnapshotState != domain.Enforced {
		t.Fatalf("after its expiry: %+v", c)
	}
	f.exec(t, `UPDATE pc.connections SET destination_class = 'internal' WHERE id = $1`, f.conn)
	if c, _ := f.svc.ClaimAt(ctx, f.org, sc, now); c == nil || c.State != domain.Partial || c.Snapshot != row.ID ||
		!c.Lapsed || c.Reason != "connection" {
		t.Fatalf("after a change: %+v", c)
	}
}

// TestHR217_AChangeAlwaysRecordsASnapshot: a change the reassess job sees
// records a snapshot even when the coverage is the same, so the claims made
// after it name a snapshot computed after the change and did not lapse.
func TestHR217_AChangeAlwaysRecordsASnapshot(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	sc := domain.Scope{Agent: f.agent, Connection: f.conn, Operation: "payments.refund.create"}
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7, 'http',
		'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), sc.Operation, f.conn)
	if _, err := f.record(t, f.closure(probes(false), f.dbNow(t))); err != nil {
		t.Fatal(err)
	}
	f.reassessOrg(t)
	before, _, _ := f.current(t, sc.Operation)
	f.exec(t, `INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id) VALUES ($1, $2, 'route', $3)`,
		f.org, ids.NewV7(), f.conn)
	if c, _ := f.svc.ClaimAt(ctx, f.org, sc, time.Now()); c == nil || !c.Lapsed || c.Snapshot != before.ID {
		t.Fatalf("before the job: %+v", c)
	}
	if r := f.reassessOrg(t); r.Snapshots != 1 {
		t.Fatalf("the job recorded %+v", r)
	}
	after, _, _ := f.current(t, sc.Operation)
	c, err := f.svc.ClaimAt(ctx, f.org, sc, time.Now())
	if err != nil || c == nil || c.Lapsed || c.Snapshot != after.ID || after.ID == before.ID || c.State != domain.Enforced {
		t.Fatalf("after the job: %+v (%v)", c, err)
	}
}

// TestHR217_AClaimDoesNotLapseOnAChangeItsSnapshotSaw: a route change the
// sandbox recorded during its session, before the closure, is read by the
// computation of the ENFORCED snapshot the closure records at once, so a claim made before the reassess
// job runs does not lapse on it; a change after the computation still
// lapses the claim.
func TestHR217_AClaimDoesNotLapseOnAChangeItsSnapshotSaw(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	sc := domain.Scope{Agent: f.agent, Connection: f.conn, Operation: "payments.refund.create"}
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7, 'http',
		'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), sc.Operation, f.conn)
	f.reassessOrg(t)
	f.exec(t, `INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, agent_id, detail)
		VALUES ($1, $2, 'route', $3, $4, 'credential')`, f.org, ids.NewV7(), f.conn, f.agent)
	if _, err := f.record(t, f.closure(probes(false), f.dbNow(t))); err != nil {
		t.Fatal(err)
	}
	row, s, _ := f.current(t, sc.Operation)
	pending := f.count(t, `SELECT count(*) FROM pc.coverage_invalidations WHERE connection_id = $1 AND reassessed_at IS NULL`, f.conn)
	if row.State != "ENFORCED" || pending == 0 || len(s.Seen) != pending {
		t.Fatalf("after the closure: %s, %d pending, seen %v", row.State, pending, s.Seen)
	}
	c, err := f.svc.ClaimAt(ctx, f.org, sc, time.Now())
	if err != nil || c == nil || c.Lapsed || c.State != domain.Enforced || c.Snapshot != row.ID {
		t.Fatalf("a claim before the reassess job: %+v (%v)", c, err)
	}
	f.exec(t, `INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id) VALUES ($1, $2, 'route', $3)`,
		f.org, ids.NewV7(), f.conn)
	if c, _ := f.svc.ClaimAt(ctx, f.org, sc, time.Now()); c == nil || !c.Lapsed || c.Reason != "route" || c.Snapshot != row.ID {
		t.Fatalf("after a change it did not see: %+v", c)
	}
}

// hookVerifier runs hook at its first read, the last read of a scope's
// evidence, and reports no passing test.
type hookVerifier struct {
	once sync.Once
	hook func()
}

func (h *hookVerifier) LastPassed(context.Context, db.TenantTx, ids.UUID, string) (*time.Time, error) {
	h.once.Do(h.hook)
	return nil, nil
}

// TestHR217_AChangeCommittedDuringTheComputationLapsesTheClaim: a change
// whose transaction began before the scope was computed, but committed
// only after its evidence was read, is not in the snapshot: the claim
// made on it lapses, although the change occurred before the computation.
func TestHR217_AChangeCommittedDuringTheComputationLapsesTheClaim(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	sc := domain.Scope{Agent: f.agent, Connection: f.conn, Operation: "payments.refund.create"}
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7, 'http',
		'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), sc.Operation, f.conn)
	f.reassessOrg(t)

	// A concurrent change: inserted, held open, committed at the last
	// evidence read of the closure's reassessment.
	inserted, commit, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, agent_id, detail)
				VALUES ($1, $2, 'route', $3, $4, 'credential')`, f.org, ids.NewV7(), f.conn, f.agent); err != nil {
				return err
			}
			close(inserted)
			<-commit
			return nil
		})
	}()
	select {
	case <-inserted:
	case err := <-done:
		t.Fatal(err)
	}
	f.svc.Verifier = &hookVerifier{hook: func() {
		close(commit)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}}
	defer func() { f.svc.Verifier = nil }()
	if _, err := f.record(t, f.closure(probes(false), f.dbNow(t))); err != nil {
		t.Fatal(err)
	}
	f.svc.Verifier = nil
	row, s, _ := f.current(t, sc.Operation)
	if row.State != "ENFORCED" || len(s.Seen) != 0 {
		t.Fatalf("after the closure: %s, seen %v", row.State, s.Seen)
	}
	if c, err := f.svc.ClaimAt(ctx, f.org, sc, time.Now()); err != nil || c == nil || !c.Lapsed || c.Reason != "route" ||
		c.Snapshot != row.ID {
		t.Fatalf("a claim on a snapshot that did not see the change: %+v (%v)", c, err)
	}
}

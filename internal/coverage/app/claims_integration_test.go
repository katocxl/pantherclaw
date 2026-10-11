// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR217_AClaimIsTheCurrentSnapshotAsItReadsAtDecisionTime: no claim for
// a scope never assessed; an ENFORCED claim names the current snapshot and
// its digest; the same snapshot claims PARTIAL after its expiry or after
// an invalidating change, never more than it records.
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
	if err != nil || c == nil || c.State != domain.Enforced || c.Snapshot != row.ID || !slices.Equal(c.Digest, row.BodySha256) {
		t.Fatalf("an ENFORCED scope: %+v (%v)", c, err)
	}
	if c, _ := f.svc.ClaimAt(ctx, f.org, sc, row.ExpiresAt.Add(time.Second)); c == nil || c.State != domain.Partial || c.Snapshot != row.ID {
		t.Fatalf("after its expiry: %+v", c)
	}
	f.exec(t, `UPDATE pc.connections SET destination_class = 'internal' WHERE id = $1`, f.conn)
	if c, _ := f.svc.ClaimAt(ctx, f.org, sc, now); c == nil || c.State != domain.Partial || c.Snapshot != row.ID {
		t.Fatalf("after a change: %+v", c)
	}
}

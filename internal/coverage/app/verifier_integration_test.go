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
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// verifier is a fake target verifier with a passing test per operation.
type verifier struct {
	passed map[string]time.Time
	asked  []string
}

func (v *verifier) LastPassed(_ context.Context, _ db.TenantTx, _ ids.UUID, operation string) (*time.Time, error) {
	v.asked = append(v.asked, operation)
	if at, ok := v.passed[operation]; ok {
		return &at, nil
	}
	return nil, nil
}

// TestHR210_AVerifierPassLiftsOnlyTheReadItTested: on target-enforced
// access, a passing target-verifier test of a read lifts that read's scope
// to ENFORCED. Another read on the same connection stays unverified, and a
// write stays PARTIAL even with a passing test of its own (founder
// decision N15).
func TestHR210_AVerifierPassLiftsOnlyTheReadItTested(t *testing.T) {
	f := newFixture(t)
	f.exec(t, "UPDATE pc.connections SET access_mode = 'target_enforced' WHERE id = $1", f.conn)
	const tested, untested, write = "payments.refund.get", "payments.refund.list", "payments.refund.create"
	now := f.dbNow(t)
	v := &verifier{passed: map[string]time.Time{tested: now.Add(-time.Minute), write: now.Add(-time.Minute)}}
	f.svc.Verifier = v
	for _, op := range []string{tested, untested, write} {
		f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
			gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7,
			'http', 'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), op, f.conn)
	}
	var revision int32
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT revision FROM pc.connections WHERE id = $1", f.conn).Scan(&revision)
	}); err != nil {
		t.Fatal(err)
	}
	c := f.closure(probes(false), f.dbNow(t))
	c.Bound.ConnectionRevision = revision
	if _, err := f.record(t, c); err != nil {
		t.Fatal(err)
	}
	f.reassess(t)
	for op, want := range map[string]struct{ state, reason string }{
		tested:   {"ENFORCED", ""},
		untested: {"PARTIAL", domain.ReasonUnverified},
		write:    {"PARTIAL", domain.ReasonWriteCapped},
	} {
		row, s, _ := f.current(t, op)
		if row.State != want.state || (want.reason != "" && !slices.Contains(s.Reasons, want.reason)) {
			t.Errorf("%s: %s %v, want %s with %q", op, row.State, s.Reasons, want.state, want.reason)
		}
	}
	for _, op := range []string{tested, untested, write} {
		if !slices.Contains(v.asked, op) {
			t.Errorf("the verifier was not asked about %s: %v", op, v.asked)
		}
	}
}

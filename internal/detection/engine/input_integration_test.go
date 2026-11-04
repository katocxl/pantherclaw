// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package engine_test

import (
	"context"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// TestHR680_EngineRecordsWhenARuleLastHadInput: a processed batch sets
// last_input_at of each rule that reads one of its events to the newest such
// event's occurred_at, with the cursor; a rule that reads none of them keeps
// none, and a later write never moves it back (G0 M28 D716).
// Covers: F960, HR-680
func TestHR680_EngineRecordsWhenARuleLastHadInput(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, billing.Community)
	const kind = "audit.security.kill_switch_engaged"
	f.audit(t, "security.kill_switch_engaged", 2, nil)
	f.drain(t)
	var newest time.Time
	got := map[string]time.Time{}
	if err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		if err := tx.QueryRow(ctx, `SELECT max(occurred_at) FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2`,
			f.org, kind).Scan(&newest); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT rule_id, last_input_at FROM pc.detection_rule_state
			WHERE org_id = $1 AND last_input_at IS NOT NULL`, f.org)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var at time.Time
			if err := rows.Scan(&id, &at); err != nil {
				return err
			}
			got[id] = at
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	const rule = "pc.containment.kill_switch_engaged"
	if !got[rule].Equal(newest) {
		t.Fatalf("%s: last input %v, want the newest event's %v", rule, got[rule], newest)
	}
	for _, c := range f.e.Builtin {
		_, have := got[c.Rule.ID]
		if reads := engine.ReadsKind(c.Rule, kind); have != reads {
			t.Errorf("%s: has a last input %v, reads the kind %v", c.Rule.ID, have, reads)
		}
	}
	// An older time never replaces a newer one.
	if err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).TouchDetectionRuleInput(ctx, f.org, rule, newest.Add(-24*time.Hour))
	}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.detection_rule_state WHERE org_id = $1 AND rule_id = $2
		AND last_input_at = $3`, f.org, rule, newest); n != 1 {
		t.Error("last_input_at moved back")
	}
}

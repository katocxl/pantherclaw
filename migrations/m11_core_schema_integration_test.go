// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// TestM11Core_PcAppUpdatesOnlyTransitions (G0 M11 part 2 D5, D6, 00140):
// pc_app may UPDATE only the transition columns of the automation tables:
// never names, kinds, identities, ids, bindings, digests of ceilings or
// change request content. Confirmations are insert-only; nothing is
// deleted; every table has RLS forced.
func TestM11Core_PcAppUpdatesOnlyTransitions(t *testing.T) {
	d := dbtest.New(t)
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	updatable := map[string][]string{
		"automations": {
			"purpose", "owner_user_id", "state", "rollout", "cohort_agents", "enabled_version_id", "pause_reason",
			"paused_at", "updated_at", "retired_at",
		},
		"automation_versions": {
			"state", "definition", "digest", "summary", "findings", "tested_run_id", "updated_at", "validated_at",
			"tested_at", "published_at", "change_request_id",
		},
		"change_requests":         {"state", "decided_at", "decided_reason"},
		"change_confirmations":    nil,
		"automation_ceilings":     {"state", "void_reason", "ended_at"},
		"automation_usage":        {"grants", "runs"},
		"automation_budget_usage": {"reserved"},
	}
	for table, allowed := range updatable {
		rows, err := m.Pgx().Query(ctx, `SELECT column_name FROM information_schema.columns
			WHERE table_schema = 'pc' AND table_name = $1 ORDER BY ordinal_position`, table)
		if err != nil {
			t.Fatal(err)
		}
		var cols []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, c)
		}
		rows.Close()
		if len(cols) < 4 {
			t.Fatalf("%s has %d columns", table, len(cols))
		}
		for _, c := range cols {
			var got bool
			if err := m.Pgx().QueryRow(ctx, `SELECT has_column_privilege('pc_app', 'pc.' || $1, $2, 'UPDATE')`, table, c).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if want := slices.Contains(allowed, c); got != want {
				t.Errorf("pc_app UPDATE on pc.%s.%s = %v, want %v", table, c, got, want)
			}
		}
		var del, forced bool
		if err := m.Pgx().QueryRow(ctx, `SELECT has_table_privilege('pc_app', 'pc.' || $1, 'DELETE'),
			(SELECT relforcerowsecurity FROM pg_class WHERE oid = ('pc.' || $1)::regclass)`, table).Scan(&del, &forced); err != nil {
			t.Fatal(err)
		}
		if del || !forced {
			t.Errorf("pc.%s: pc_app DELETE %v, RLS forced %v", table, del, forced)
		}
	}
	// pc_app never re-assigns a service account's automation.
	var got bool
	if err := m.Pgx().QueryRow(ctx, `SELECT has_column_privilege('pc_app', 'pc.service_accounts', 'automation_id', 'UPDATE')`).Scan(&got); err != nil || got {
		t.Errorf("pc_app may UPDATE pc.service_accounts.automation_id: %v %v", got, err)
	}
}

// TestHR271_DatabaseRefusesServiceAccountRootGrantWithoutCeiling: the
// person-only root rule is replaced by grants_root_grantor and
// grants_ceiling, never dropped (G0 M11 part 2 D9).
func TestHR271_DatabaseRefusesServiceAccountRootGrantWithoutCeiling(t *testing.T) {
	d := dbtest.New(t)
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	defs := map[string]string{}
	rows, err := m.Pgx().Query(ctx, `SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid = 'pc.grants'::regclass AND contype = 'c'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n, def string
		if err := rows.Scan(&n, &def); err != nil {
			t.Fatal(err)
		}
		defs[n] = def
	}
	rows.Close()
	if _, ok := defs["grants_root_by_a_person"]; ok {
		t.Error("grants_root_by_a_person still present")
	}
	root, ceiling := defs["grants_root_grantor"], defs["grants_ceiling"]
	if !strings.Contains(root, "service_account") || !strings.Contains(root, "ceiling_id IS NOT NULL") {
		t.Errorf("grants_root_grantor = %q", root)
	}
	if !strings.Contains(ceiling, "ceiling_id IS NULL") || !strings.Contains(ceiling, "parent_id IS NULL") {
		t.Errorf("grants_ceiling = %q", ceiling)
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// TestHR230_PcAppUpdatesOnlyTheGateTransitions (G0 M11.1 D22, 00110):
// pc_app may UPDATE a policy version's state and publication only, and a
// change request's decision only: never content, digests, bindings,
// summaries, requesters or ids. Validations, test runs and confirmations
// are insert-only (no UPDATE, no DELETE), and every table has RLS forced.
func TestHR230_PcAppUpdatesOnlyTheGateTransitions(t *testing.T) {
	d := dbtest.New(t)
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	updatable := map[string][]string{
		"policy_versions":             {"state", "published_by", "published_at"},
		"policy_change_requests":      {"state", "decided_at", "decided_reason"},
		"policy_validations":          nil,
		"policy_test_runs":            nil,
		"policy_change_confirmations": nil,
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
		if len(cols) < 5 {
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
	for _, c := range []string{"content_digest", "binding", "summary", "requested_by"} {
		table := "policy_change_requests"
		if c == "content_digest" {
			table = "policy_versions"
		}
		var got bool
		if err := m.Pgx().QueryRow(ctx, `SELECT has_column_privilege('pc_app', 'pc.' || $1, $2, 'UPDATE')`, table, c).Scan(&got); err != nil || got {
			t.Errorf("pc_app may UPDATE pc.%s.%s: %v %v", table, c, got, err)
		}
	}
}

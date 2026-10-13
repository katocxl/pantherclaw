// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"io/fs"
	"maps"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/migrations"
)

// TestHR206_ConsequenceVerificationRoundTrips (G0 M8 W1c): 00095 lets a
// verification task be a consequence's, which carries its own definition
// and window start (and only it), links a consequence to its action, and
// opens consequence_unconfirmed reconciliations. Its Down section, run as
// pc_migrator, restores every check exactly with row-level security forced
// again, and its Up section applies again.
func TestHR206_ConsequenceVerificationRoundTrips(t *testing.T) {
	d := dbtest.New(t)
	b, err := fs.ReadFile(migrations.FS, "00095_consequence_verification.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatal("no Down section")
	}
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	exec := func(sql string) {
		t.Helper()
		if _, err := m.Pgx().Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	checks := func() map[string]string {
		t.Helper()
		rows, err := m.Pgx().Query(ctx, `SELECT 'pc.' || (SELECT relname FROM pg_class WHERE oid = conrelid) || '.' || conname, pg_get_constraintdef(oid) FROM pg_constraint
			WHERE conrelid IN ('pc.verifications'::regclass, 'pc.transaction_links'::regclass, 'pc.reconciliation_tasks'::regclass)
			  AND contype = 'c' AND (pg_get_constraintdef(oid) LIKE '%purpose%' OR pg_get_constraintdef(oid) LIKE '%kind%')`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var name, def string
			if err := rows.Scan(&name, &def); err != nil {
				t.Fatal(err)
			}
			out[name] = def
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	after := checks()
	for name, want := range map[string]string{
		"pc.verifications.verifications_purpose":                  "'consequence'",
		"pc.verifications.verifications_basis":                    "purpose = 'consequence'",
		"pc.transaction_links.transaction_links_kind_check":       "'consequence'",
		"pc.reconciliation_tasks.reconciliation_tasks_kind_check": "'consequence_unconfirmed'",
	} {
		if !strings.Contains(after[name], want) {
			t.Errorf("%s = %q, want it to name %s", name, after[name], want)
		}
	}

	exec(down)
	before := checks()
	if _, ok := before["pc.verifications.verifications_basis"]; ok {
		t.Error("after Down, verifications_basis is still there")
	}
	for name, def := range before {
		if strings.Contains(def, "consequence") {
			t.Errorf("after Down, %s still allows a consequence: %s", name, def)
		}
	}
	for _, name := range []string{
		"pc.verifications.verifications_purpose", "pc.transaction_links.transaction_links_kind_check",
		"pc.reconciliation_tasks.reconciliation_tasks_kind_check",
	} {
		if before[name] == "" {
			t.Errorf("after Down, %s is gone", name)
		}
	}
	var forced int
	if err := m.Pgx().QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE oid IN ('pc.verifications'::regclass,
		'pc.observations'::regclass, 'pc.reconciliation_tasks'::regclass, 'pc.transaction_links'::regclass) AND relforcerowsecurity`).Scan(&forced); err != nil ||
		forced != 4 {
		t.Fatalf("after Down, RLS is forced on %d of 4 tables: %v", forced, err)
	}

	exec(up)
	if again := checks(); !maps.Equal(again, after) {
		t.Errorf("after Up again: %v, want %v", again, after)
	}
}

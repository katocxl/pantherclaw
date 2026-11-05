// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/migrations"
)

// m29Checks are the CHECKs 00330 and 00331 widen and a value each must now
// admit: the connection kind model, the run owner of a budget account and
// the run's rank 6.
var m29Checks = []struct{ table, constraint, value string }{
	{"pc.connections", "connections_kind_check", "'model'"},
	{"pc.budget_accounts", "budget_accounts_owner_kind_check", "'run'"},
	{"pc.budget_accounts", "budget_accounts_rank_check", "6"},
}

// TestM29_00330To00332WidenTheChecksAndDownRestoresThem (G0 M29 D811,
// D821, D825; D878): after Up the connection kind model, the run owner and
// rank 6 are admitted, each CHECK validated, and pc.model_connections and
// pc.model_usage exist; the Down sections (newest first) restore the old
// CHECKs and drop the tables; the Up sections apply again.
func TestM29_00330To00332WidenTheChecksAndDownRestoresThem(t *testing.T) {
	d := dbtest.New(t)
	files := []string{"00330_model_connections.sql", "00331_token_budgets.sql", "00332_model_usage.sql"}
	var ups, downs []string
	for _, f := range files {
		b, err := fs.ReadFile(migrations.FS, f)
		if err != nil {
			t.Fatal(err)
		}
		up, down, ok := strings.Cut(string(b), "-- +goose Down")
		if !ok {
			t.Fatalf("%s: no Down section", f)
		}
		ups, downs = append(ups, up), append(downs, down)
	}
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	admits := func() int {
		t.Helper()
		n := 0
		for _, c := range m29Checks {
			var def string
			var valid bool
			if err := m.Pgx().QueryRow(ctx, `SELECT pg_get_constraintdef(oid), convalidated FROM pg_constraint
				WHERE conrelid = $1::regclass AND conname = $2`, c.table, c.constraint).Scan(&def, &valid); err != nil {
				t.Fatalf("%s %s: %v", c.table, c.constraint, err)
			}
			if !valid {
				t.Errorf("%s %s is not validated", c.table, c.constraint)
			}
			if strings.Contains(def, c.value) {
				n++
			}
		}
		return n
	}
	tables := func() int {
		t.Helper()
		var n int
		if err := m.Pgx().QueryRow(ctx, `SELECT count(*) FROM pg_tables WHERE schemaname = 'pc'
			AND tablename IN ('model_connections', 'model_usage')`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n, tb := admits(), tables(); n != len(m29Checks) || tb != 2 {
		t.Fatalf("after Up: %d of %d values admitted, %d tables", n, len(m29Checks), tb)
	}
	for _, down := range slices.Backward(downs) {
		if _, err := m.Pgx().Exec(ctx, down); err != nil {
			t.Fatalf("Down: %v", err)
		}
	}
	if n, tb := admits(), tables(); n != 0 || tb != 0 {
		t.Fatalf("after Down: %d values admitted, %d tables", n, tb)
	}
	for _, up := range ups {
		if _, err := m.Pgx().Exec(ctx, up); err != nil {
			t.Fatalf("Up again: %v", err)
		}
	}
	if n, tb := admits(), tables(); n != len(m29Checks) || tb != 2 {
		t.Fatalf("after Up again: %d of %d values admitted, %d tables", n, len(m29Checks), tb)
	}
}

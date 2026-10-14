// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/migrations"
)

// rangeFlags are the four columns 00096 adds: the mark on an agent and the
// simulated flag of a run, a transaction and a connection.
var rangeFlags = [][2]string{
	{"pc.agents", "range_agent"}, {"pc.runs", "simulated"}, {"pc.transactions", "simulated"}, {"pc.connections", "simulated"},
}

// TestHR220_RangeFlagsCannotBeUpdated (G0 M12 W1a): the four flags are boolean
// NOT NULL DEFAULT false, pc_app can set them when it inserts a row and can
// never update them, so a real agent cannot become a range agent, a real run
// cannot become simulated, and the reverse.
func TestHR220_RangeFlagsCannotBeUpdated(t *testing.T) {
	d := dbtest.New(t)
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	for _, f := range rangeFlags {
		var typ, nullable, def string
		if err := m.Pgx().QueryRow(ctx, `SELECT data_type, is_nullable, column_default FROM information_schema.columns
			WHERE table_schema = 'pc' AND table_name = $1 AND column_name = $2`, strings.TrimPrefix(f[0], "pc."), f[1]).
			Scan(&typ, &nullable, &def); err != nil {
			t.Fatalf("%s.%s: %v", f[0], f[1], err)
		}
		if typ != "boolean" || nullable != "NO" || def != "false" {
			t.Errorf("%s.%s is %s nullable=%s default=%s, want boolean NOT NULL DEFAULT false", f[0], f[1], typ, nullable, def)
		}
		for priv, want := range map[string]bool{"INSERT": true, "UPDATE": false} {
			var got bool
			if err := m.Pgx().QueryRow(ctx, `SELECT has_column_privilege('pc_app', $1, $2, $3)`, f[0], f[1], priv).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("pc_app %s on %s.%s = %v, want %v", priv, f[0], f[1], got, want)
			}
		}
	}
}

// TestHR220_00096DownRemovesTheFlagsAndUpAppliesAgain: the Down section
// removes the four columns, and the Up section applies again.
func TestHR220_00096DownRemovesTheFlagsAndUpAppliesAgain(t *testing.T) {
	d := dbtest.New(t)
	b, err := fs.ReadFile(migrations.FS, "00096_range_boundary.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatal("no Down section")
	}
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	have := func() int {
		t.Helper()
		n := 0
		for _, f := range rangeFlags {
			var ok bool
			if err := m.Pgx().QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'pc' AND table_name = $1 AND column_name = $2)`, strings.TrimPrefix(f[0], "pc."), f[1]).Scan(&ok); err != nil {
				t.Fatal(err)
			}
			if ok {
				n++
			}
		}
		return n
	}
	if n := have(); n != 4 {
		t.Fatalf("%d of 4 flags before Down", n)
	}
	if _, err := m.Pgx().Exec(ctx, down); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if n := have(); n != 0 {
		t.Fatalf("%d of 4 flags after Down, want 0", n)
	}
	if _, err := m.Pgx().Exec(ctx, up); err != nil {
		t.Fatalf("Up again: %v", err)
	}
	if n := have(); n != 4 {
		t.Fatalf("%d of 4 flags after Up again", n)
	}
}

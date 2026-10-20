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

// TestM14_00151PostgresConnections (G0 M14 D64): the postgres connection
// configuration table is tenant-isolated with forced row security, belongs
// to its connection, never grants pc_app a DELETE, and Down then Up
// applies cleanly.
func TestM14_00151PostgresConnections(t *testing.T) {
	d := dbtest.New(t)
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	check := func() {
		t.Helper()
		var rls, forced, fk, del bool
		if err := m.Pgx().QueryRow(ctx, `SELECT c.relrowsecurity, c.relforcerowsecurity,
			EXISTS (SELECT FROM pg_constraint WHERE conrelid = c.oid AND contype = 'f' AND confrelid = 'pc.connections'::regclass),
			has_table_privilege('pc_app', c.oid, 'DELETE')
			FROM pg_class c WHERE c.oid = 'pc.postgres_connections'::regclass`).Scan(&rls, &forced, &fk, &del); err != nil {
			t.Fatal(err)
		}
		if !rls || !forced || !fk || del {
			t.Fatalf("rls %v forced %v fk %v delete %v", rls, forced, fk, del)
		}
	}
	check()
	b, err := fs.ReadFile(migrations.FS, "00151_m14_data.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatal("no Down section")
	}
	if _, err := m.Pgx().Exec(ctx, down); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if _, err := m.Pgx().Exec(ctx, up); err != nil {
		t.Fatalf("Up again: %v", err)
	}
	check()
}

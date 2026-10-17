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

// m14Checks are the CHECKs 00150 widens and a value each must now admit.
var m14Checks = []struct{ table, constraint, value string }{
	{"pc.connections", "connections_kind_check", "'postgres'"},
	{"pc.connections", "connections_kind_check", "'a2a'"},
	{"pc.connections", "connections_base_url_kind", "'postgres'"},
	{"pc.transactions", "transactions_channel_check", "'authzen'"},
	{"pc.transactions", "transactions_channel_check", "'a2a'"},
	{"pc.coverage_routes", "coverage_routes_channel_check", "'authzen'"},
	{"pc.coverage_routes", "coverage_routes_channel_check", "'a2a'"},
	{"pc.notification_channels", "notification_channels_kind_check", "'slack_app'"},
	{"pc.notification_channels", "notification_channels_secret_kind", "'slack_app'"},
	{"pc.deliveries", "deliveries_kind_check", "'slack_app'"},
}

// TestM14_00150WidensTheChecksAndDownRestoresThem (G0 M14 D6): the
// connection kinds postgres and a2a, the channels authzen and a2a on
// transactions and coverage routes, and the notification kind slack_app
// (whose bot token is the channel's secret) are admitted, each CHECK
// validated; the Down section restores the old CHECKs, and the Up section
// applies again.
func TestM14_00150WidensTheChecksAndDownRestoresThem(t *testing.T) {
	d := dbtest.New(t)
	b, err := fs.ReadFile(migrations.FS, "00150_m14_core.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatal("no Down section")
	}
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	admits := func() int {
		t.Helper()
		n := 0
		for _, c := range m14Checks {
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
	if n := admits(); n != len(m14Checks) {
		t.Fatalf("%d of %d values admitted after Up", n, len(m14Checks))
	}
	if _, err := m.Pgx().Exec(ctx, down); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if n := admits(); n != 0 {
		t.Fatalf("%d values still admitted after Down", n)
	}
	if _, err := m.Pgx().Exec(ctx, up); err != nil {
		t.Fatalf("Up again: %v", err)
	}
	if n := admits(); n != len(m14Checks) {
		t.Fatalf("%d of %d values admitted after Up again", n, len(m14Checks))
	}
}

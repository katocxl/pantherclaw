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

// TestHR222_00098DownCollapsesTheConnectionScopesAndUpAppliesAgain (D43):
// with a real connection and its twin each supplying and holding the same
// fact, the Down section keeps the newest fact and one active declaration,
// removes the columns and restores the one-value and one-provider keys; the
// Up section applies again and sets the connection on gateway facts.
func TestHR222_00098DownCollapsesTheConnectionScopesAndUpAppliesAgain(t *testing.T) {
	d := dbtest.New(t)
	b, err := fs.ReadFile(migrations.FS, "00098_facts_per_connection.sql")
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
	count := func(sql string) int {
		t.Helper()
		var n int
		d.AdminQueryRow(t, sql, nil, &n)
		return n
	}
	columns := func() int {
		return count(`SELECT count(*) FROM information_schema.columns WHERE table_schema = 'pc' AND column_name = 'connection_id'
			AND table_name IN ('facts', 'fact_declarations')`)
	}
	const org, gw, c1, c2, p1, p2 = "5e1c0d9a-98a0-7000-8000-000000000001", "00000000-0000-7000-8000-000000000002",
		"00000000-0000-7000-8000-0000000000c1", "00000000-0000-7000-8000-0000000000c2",
		"00000000-0000-7000-8000-0000000000b1", "00000000-0000-7000-8000-0000000000b2"
	d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ('"+org+"', 'acme')")
	d.AdminExec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ('"+org+"', '"+gw+"', 'edge', 'test')")
	for _, c := range [][2]string{{c1, "github"}, {c2, "github-sim"}} {
		d.AdminExec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode, created_by, updated_by)
			VALUES ('`+org+`', '`+c[0]+`', '`+c[1]+`', 'http', '`+gw+`', 'pc.github', 'https://api.github.com', 'none', 'enforce', 'test', 'test')`)
	}
	for _, p := range [][3]string{{p1, "github", c1}, {p2, "github.sim", c2}} {
		d.AdminExec(t, `INSERT INTO pc.fact_providers (org_id, id, name, gateway_id, connection_id, created_by)
			VALUES ('`+org+`', '`+p[0]+`', '`+p[1]+`', '`+gw+`', '`+p[2]+`', 'test')`)
		d.AdminExec(t, `INSERT INTO pc.fact_declarations (org_id, provider_id, name, value_type, subject_type, max_lag_s, connection_id)
			VALUES ('`+org+`', '`+p[0]+`', 'github.pull.head', 'object', 'github.pull_request', 60, '`+p[2]+`')`)
		d.AdminExec(t, `INSERT INTO pc.facts (org_id, id, name, subject_type, subject_id, provider_id, value, observed_at, connection_id)
			VALUES ('`+org+`', gen_random_uuid(), 'github.pull.head', 'github.pull_request', 'acme/x#1', '`+p[0]+`', '\x7b7d',
			now() - interval '`+map[string]string{p1: "2", p2: "1"}[p[0]]+` minutes', '`+p[2]+`')`)
	}
	if columns() != 2 {
		t.Fatalf("%d connection columns before Down, want 2", columns())
	}

	// A real rollback runs 00181's Down, which drops the org write guards,
	// before it reaches 00098; this test runs 00098 alone on the full
	// schema, so it sets the guards on its two tables aside meanwhile.
	guards := func(op string) {
		t.Helper()
		exec("ALTER TABLE pc.facts " + op + " TRIGGER org_write_guard; ALTER TABLE pc.fact_declarations " + op + " TRIGGER org_write_guard")
	}
	guards("DISABLE")
	exec(down)
	if columns() != 0 {
		t.Fatalf("%d connection columns after Down", columns())
	}
	if n := count("SELECT count(*) FROM pc.facts"); n != 1 {
		t.Errorf("%d facts after Down, want the newest only", n)
	}
	if n := count("SELECT count(*) FROM pc.fact_declarations WHERE active"); n != 1 {
		t.Errorf("%d active declarations after Down, want one", n)
	}
	if n := count(`SELECT count(*) FROM pg_constraint WHERE conrelid = 'pc.facts'::regclass AND contype = 'u'`); n != 1 {
		t.Errorf("%d unique constraints on facts after Down, want the original one", n)
	}

	exec(up)
	guards("ENABLE")
	if columns() != 2 {
		t.Fatalf("%d connection columns after Up again", columns())
	}
	if n := count(`SELECT count(*) FROM pg_class WHERE oid IN ('pc.connections'::regclass, 'pc.fact_providers'::regclass,
		'pc.fact_declarations'::regclass, 'pc.facts'::regclass) AND relforcerowsecurity`); n != 4 {
		t.Errorf("row-level security is forced on %d of 4 tables after Up again", n)
	}
	if n := count("SELECT count(*) FROM pc.facts WHERE connection_id IS NOT NULL"); n != 1 {
		t.Errorf("%d gateway facts with a connection after Up again, want 1", n)
	}
	if n := count(`SELECT count(*) FROM pg_trigger WHERE tgname = 'fact_declarations_one_scope' AND NOT tgisinternal`); n != 1 {
		t.Errorf("the scope trigger is missing after Up again")
	}
}

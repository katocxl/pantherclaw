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

// TestHR160_00081DownRemovesWhatOnlyItAllowsAndUpAppliesAgain (#297 review
// follow-up): with the later migrations stepped back, 00081's Down section,
// run as pc_migrator over rows only 00081 allows (a gateway fact provider
// with an object declaration and a large fact, a GitHub identity, a
// connection's installation, an organization scan, its lease and its
// finding), removes those rows and its tables, and every Up section then
// applies again.
func TestHR160_00081DownRemovesWhatOnlyItAllowsAndUpAppliesAgain(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	section := func(name string) (up, down string) {
		t.Helper()
		b, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		up, down, ok := strings.Cut(string(b), "-- +goose Down")
		if !ok {
			t.Fatalf("%s has no Down section", name)
		}
		return up, down
	}
	exec := func(what, sql string) {
		t.Helper()
		if _, err := m.Pgx().Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	exists := func(table string) bool {
		t.Helper()
		var ok bool
		if err := m.Pgx().QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", table).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	count := func(sql string) int {
		t.Helper()
		var n int
		if err := m.Pgx().QueryRow(ctx, sql).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// Every migration after 00081, newest first (D17): a later one's checks
	// would refuse 00084 applying again over rows they never saw.
	all, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	var later []string
	for _, name := range all {
		if name > "00081_github_facts.sql" {
			later = append(later, name)
		}
	}
	slices.Sort(later)
	slices.Reverse(later)
	if len(later) < 3 || later[len(later)-1] != "00082_release_controls.sql" {
		t.Fatalf("later migrations %v", later)
	}
	for _, name := range later {
		_, down := section(name)
		exec(name+" Down", down)
	}

	f.mustExec(t, m8gProvider, f.org, m5ID(), "github", nil, f.gateway, f.connection)
	f.mustExec(t, `INSERT INTO pc.fact_declarations (org_id, provider_id, name, value_type, subject_type, max_lag_s)
		SELECT org_id, id, 'github.pull.head', 'object', 'github.pull_request', 30 FROM pc.fact_providers WHERE name = 'github'`)
	f.mustExec(t, `INSERT INTO pc.facts (org_id, id, name, subject_type, subject_id, provider_id, value, observed_at)
		SELECT org_id, gen_random_uuid(), 'github.pull.head', 'github.pull_request', 'acme/payments#7', id, convert_to(repeat('x', 8000), 'UTF8'), now()
		FROM pc.fact_providers WHERE name = 'github'`)
	f.mustExec(t, `INSERT INTO pc.github_identities (org_id, id, user_id, github_login, github_user_id, linked_by)
		VALUES ($1, $2, $3, 'alice', 101, 'test')`, f.org, m5ID(), f.user)
	f.mustExec(t, `INSERT INTO pc.connection_github (org_id, connection_id, app_client_id, installation_id, account_login, updated_by)
		VALUES ($1, $2, 'Iv23liApp', 7, 'acme', 'test')`, f.org, f.connection)
	f.mustExec(t, `INSERT INTO pc.github_scan_runs (org_id, id, connection_id, started_by) VALUES ($1, $2, $3, 'test')`, f.org, m5ID(), f.connection)
	f.mustExec(t, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key) VALUES ($1, $2, $3, 'github_scan', $4)`,
		f.org, m5ID(), f.agent, m5Secret(9))
	f.mustExec(t, m7Verification, f.org, m5ID(), "org_scan", nil, f.connection, nil, nil)

	up81, down81 := section("00081_github_facts.sql")
	exec("00081 Down", down81)
	for _, table := range []string{"pc.connection_github", "pc.github_identities", "pc.github_scan_runs"} {
		if exists(table) {
			t.Errorf("after Down, %s is still there", table)
		}
	}
	for what, sql := range map[string]string{
		"gateway providers":   "SELECT count(*) FROM pc.fact_providers WHERE name = 'github'",
		"object declarations": "SELECT count(*) FROM pc.fact_declarations WHERE name = 'github.pull.head'",
		"large facts":         "SELECT count(*) FROM pc.facts WHERE octet_length(value) > 1024",
		"scan findings":       "SELECT count(*) FROM pc.discoveries WHERE source NOT IN ('gateway', 'scan')",
		"org scan leases":     "SELECT count(*) FROM pc.verifications WHERE purpose NOT IN ('follow_up', 'reconcile', 'target_log')",
	} {
		if n := count(sql); n != 0 {
			t.Errorf("after Down, %d %s are left", n, what)
		}
	}
	var forced int
	if err := m.Pgx().QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE oid IN ('pc.verifications'::regclass, 'pc.discoveries'::regclass,
		'pc.fact_providers'::regclass, 'pc.fact_declarations'::regclass, 'pc.facts'::regclass) AND relforcerowsecurity`).Scan(&forced); err != nil || forced != 5 {
		t.Fatalf("after Down, RLS is forced on %d of 5 tables: %v", forced, err)
	}

	exec("00081 Up", up81)
	for i := len(later) - 1; i >= 0; i-- {
		up, _ := section(later[i])
		exec(later[i]+" Up", up)
	}
	for _, table := range []string{"pc.connection_github", "pc.github_identities", "pc.github_scan_runs"} {
		if !exists(table) {
			t.Errorf("after Up again, %s is missing", table)
		}
	}
}

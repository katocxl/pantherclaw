// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"io/fs"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/migrations"
)

// These tests check the schema's second line of defense for G0 M8 track C
// (migration 00084): the application enforces the same rules first. Names
// are prefixed m8c so that they never collide with other milestones'
// schema tests in this package.

const (
	m8cCredentialTest = `INSERT INTO pc.connection_tests (org_id, id, connection_id, kind, state, result, checks, requested_by, finished_at)
		VALUES ($1, $2, $3, 'credential', 'DONE', 'PASSED', '[]', 'test', now())`
	m8cLeasedTest = `INSERT INTO pc.connection_tests (org_id, id, connection_id, kind, verification_id, requested_by)
		VALUES ($1, $2, $3, $4, $5, 'test')`
	m8cDeclaration = `INSERT INTO pc.connection_capabilities (org_id, id, connection_id, connection_revision, declaration, declaration_sha256)
		VALUES ($1, $2, $3, 1, '{}', ` + m5Hash + `)`
)

// m8cConnection is a fixture with a gateway and one of its connections.
func m8cConnection(t *testing.T, f m5Fixture) (gateway, conn string) {
	t.Helper()
	gateway, conn = m5ID(), m5ID()
	f.mustExec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", f.org, gateway)
	f.mustExec(t, m6Connection, f.org, conn, "payments", "http", gateway, "https://api.example.com", "none")
	return gateway, conn
}

// TestF354_ConnectionTestsAreKeptAsEvidence: pc_app records a credential
// test with its result, and a leased test only with its verification task
// of purpose connection_test, which belongs to no transaction. An open
// test moves to its result; a finished test needs its time, a done one its
// result. Nothing changes what a test is or deletes it.
func TestF354_ConnectionTestsAreKeptAsEvidence(t *testing.T) {
	d := dbtest.New(t)
	f := newM5Fixture(t, d.AppPool(t))
	gw, conn := m8cConnection(t, f)
	f.mustExec(t, m8cCredentialTest, f.org, m5ID(), conn)
	task := m5ID()
	f.mustExec(t, m7Verification, f.org, task, "connection_test", nil, conn, nil, nil)
	f.want(t, m5Check, "a connection test with a transaction", m7Verification, f.org, m5ID(), "connection_test", m5ID(), conn, nil, nil)
	f.want(t, m5Check, "a follow-up without a transaction", m7Verification, f.org, m5ID(), "follow_up", nil, conn, nil, nil)
	read := m5ID()
	f.mustExec(t, m8cLeasedTest, f.org, read, conn, "read", task)
	f.want(t, m5Check, "a leased test without its task", m8cLeasedTest, f.org, m5ID(), conn, "target_verifier", nil)
	f.want(t, m5Check, "a credential test with a task", m8cLeasedTest, f.org, m5ID(), conn, "credential", task)
	f.want(t, m5Check, "another kind", m8cLeasedTest, f.org, m5ID(), conn, "write", task)
	f.want(t, m5Check, "done without a result", `UPDATE pc.connection_tests SET state = 'DONE', finished_at = now() WHERE id = $1`, read)
	f.want(t, m5Check, "finished without a time", `UPDATE pc.connection_tests SET state = 'FAILED' WHERE id = $1`, read)
	f.mustExec(t, `UPDATE pc.connection_tests SET state = 'DONE', result = 'FAILED', gateway_id = $2, finished_at = now() WHERE id = $1`, read, gw)
	f.want(t, m5Denied, "change the kind", "UPDATE pc.connection_tests SET kind = kind")
	f.want(t, m5Denied, "change who asked", "UPDATE pc.connection_tests SET requested_by = requested_by")
	f.want(t, m5Denied, "DELETE connection_tests", "DELETE FROM pc.connection_tests")
}

// TestF353_OneCurrentCapabilityDeclarationPerConnection: a connection has
// at most one declaration that is not superseded; an approval names its
// subset, who approved and when, and a superseded declaration its time.
// Declarations are never deleted, and tool observations never change.
func TestF353_OneCurrentCapabilityDeclarationPerConnection(t *testing.T) {
	d := dbtest.New(t)
	f := newM5Fixture(t, d.AppPool(t))
	_, conn := m8cConnection(t, f)
	first := m5ID()
	f.mustExec(t, m8cDeclaration, f.org, first, conn)
	f.want(t, m5Unique, "two current declarations", m8cDeclaration, f.org, m5ID(), conn)
	f.want(t, m5Check, "approved without who", `UPDATE pc.connection_capabilities SET state = 'APPROVED', approved = '{}' WHERE id = $1`, first)
	f.want(t, m5Check, "an approver without the subset", `UPDATE pc.connection_capabilities SET approved_by = 'alice', approved_at = now()
		WHERE id = $1`, first)
	f.mustExec(t, `UPDATE pc.connection_capabilities SET state = 'APPROVED', approved = '{}', approved_by = 'alice', approved_at = now()
		WHERE id = $1`, first)
	f.want(t, m5Check, "superseded without a time", `UPDATE pc.connection_capabilities SET state = 'SUPERSEDED' WHERE id = $1`, first)
	f.mustExec(t, `UPDATE pc.connection_capabilities SET state = 'SUPERSEDED', superseded_at = now() WHERE id = $1`, first)
	f.mustExec(t, m8cDeclaration, f.org, m5ID(), conn)
	f.want(t, m5Denied, "change the declaration", "UPDATE pc.connection_capabilities SET declaration = declaration")
	f.want(t, m5Denied, "DELETE connection_capabilities", "DELETE FROM pc.connection_capabilities")
	f.want(t, m5Denied, "UPDATE tool_observations", "UPDATE pc.tool_observations SET tool = tool")
	f.want(t, m5Denied, "DELETE tool_observations", "DELETE FROM pc.tool_observations")
}

// TestF354_ConnectionTestPurposeKeepsEveryEarlierOne (V1): 00084 adds
// connection_test to the verification purposes, and to those that belong
// to no transaction, under the checks' own names and keeping every purpose
// they allowed before (00060's, and 00081's when it is there). Its Down
// section, run as pc_migrator, restores the checks exactly and deletes
// the connection test tasks; its Up section applies again.
func TestF354_ConnectionTestPurposeKeepsEveryEarlierOne(t *testing.T) {
	d := dbtest.New(t)
	b, err := fs.ReadFile(migrations.FS, "00084_sdk_connections.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatal("no Down section")
	}
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	checks := func() map[string]string {
		t.Helper()
		rows, err := m.Pgx().Query(ctx, `SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint
			WHERE conrelid = 'pc.verifications'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%purpose%'
			  AND pg_get_constraintdef(oid) NOT LIKE '%window_start%'`)
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
		if err := rows.Err(); err != nil || len(out) != 2 {
			t.Fatalf("purpose checks %v: %v", out, err)
		}
		return out
	}
	quoted := regexp.MustCompile(`'([a-z_]+)'`)
	purposes := func(def string) []string {
		var out []string
		for _, s := range quoted.FindAllStringSubmatch(def, -1) {
			out = append(out, s[1])
		}
		return out
	}
	after := checks()
	for name, def := range after {
		got, want := purposes(def), []string{"target_log", "connection_test"}
		if !strings.Contains(def, "transaction_id IS NULL") {
			want = []string{"follow_up", "reconcile", "target_log", "connection_test"}
		}
		for _, p := range want {
			if !slices.Contains(got, p) {
				t.Errorf("%s does not allow %s: %s", name, p, def)
			}
		}
		if got[len(got)-1] != "connection_test" {
			t.Errorf("%s: connection_test is not added last: %s", name, def)
		}
	}
	f := newM5Fixture(t, d.AppPool(t))
	_, conn := m8cConnection(t, f)
	f.mustExec(t, m7Verification, f.org, m5ID(), "connection_test", nil, conn, nil, nil)
	exec := func(sql string) {
		t.Helper()
		if _, err := m.Pgx().Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(down)
	var forced int
	if err := m.Pgx().QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE oid IN ('pc.verifications'::regclass, 'pc.observations'::regclass)
		AND relforcerowsecurity`).Scan(&forced); err != nil || forced != 2 {
		t.Fatalf("after Down, RLS is forced on %d of 2 tables: %v", forced, err)
	}
	before := checks()
	for name, def := range after {
		earlier := slices.DeleteFunc(purposes(def), func(p string) bool { return p == "connection_test" })
		list := "'" + strings.Join(earlier, "', '") + "'"
		check := "CHECK (purpose IN (" + list + "))"
		if strings.Contains(def, "transaction_id IS NULL") {
			check = "CHECK ((purpose IN (" + list + ")) = (transaction_id IS NULL))"
		}
		exec("ALTER TABLE pc.verifications ADD CONSTRAINT m8c_expected " + check + " NOT VALID")
		var want string
		if err := m.Pgx().QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
			WHERE conrelid = 'pc.verifications'::regclass AND conname = 'm8c_expected'`).Scan(&want); err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSuffix(before[name], " NOT VALID"); got != strings.TrimSuffix(want, " NOT VALID") {
			t.Errorf("after Down, %s is %s, want %s", name, before[name], want)
		}
		exec("ALTER TABLE pc.verifications DROP CONSTRAINT m8c_expected")
	}
	exec(up)
	if again := checks(); !maps.Equal(again, after) {
		t.Errorf("after Up again: %v, want %v", again, after)
	}
}

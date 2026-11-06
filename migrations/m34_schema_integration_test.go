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

// These tests check migrations 00380–00382 (G0 M34 D990, D991, D997,
// D997a). Names carry m34 so that they never collide with other schema
// tests.

// m34Channels are the CHECKs 00380 widens with the channel runtime.
var m34Channels = []struct{ table, constraint string }{
	{"pc.transactions", "transactions_channel_check"},
	{"pc.coverage_routes", "coverage_routes_channel_check"},
}

// TestHR760_00380AdmitsChannelRuntimeAndDownRestoresIt: transactions and
// coverage routes admit the channel runtime, each CHECK validated; the Down
// section restores the old CHECKs and the Up section applies again.
//
// Covers: F1040, HR-760
func TestHR760_00380AdmitsChannelRuntimeAndDownRestoresIt(t *testing.T) {
	d := dbtest.New(t)
	b, err := fs.ReadFile(migrations.FS, "00380_runtime_channel.sql")
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
		for _, c := range m34Channels {
			var def string
			var valid bool
			if err := m.Pgx().QueryRow(ctx, `SELECT pg_get_constraintdef(oid), convalidated FROM pg_constraint
				WHERE conrelid = $1::regclass AND conname = $2`, c.table, c.constraint).Scan(&def, &valid); err != nil {
				t.Fatalf("%s %s: %v", c.table, c.constraint, err)
			}
			if !valid {
				t.Errorf("%s %s is not validated", c.table, c.constraint)
			}
			if !strings.Contains(def, "'a2a'") {
				t.Errorf("%s %s lost an earlier channel: %s", c.table, c.constraint, def)
			}
			if strings.Contains(def, "'runtime'") {
				n++
			}
		}
		return n
	}
	if n := admits(); n != len(m34Channels) {
		t.Fatalf("%d of %d CHECKs admit runtime after Up", n, len(m34Channels))
	}
	if _, err := m.Pgx().Exec(ctx, down); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if n := admits(); n != 0 {
		t.Fatalf("%d CHECKs still admit runtime after Down", n)
	}
	if _, err := m.Pgx().Exec(ctx, up); err != nil {
		t.Fatalf("Up again: %v", err)
	}
	if n := admits(); n != len(m34Channels) {
		t.Fatalf("%d of %d CHECKs admit runtime after Up again", n, len(m34Channels))
	}
}

// TestHR762_ARuntimeTargetNamesOneLiveConnectionPerOrg: a runtime target is
// 1..512 characters and names one live connection per org (00381); a
// retired connection frees it, and another org may use the same target.
//
// Covers: F1040, HR-762
func TestHR762_ARuntimeTargetNamesOneLiveConnectionPerOrg(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	target := "agentcore:arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-1/orders"
	set := "UPDATE pc.connections SET runtime_target = $1 WHERE id = $2"
	gwA := m15Gateway(t, a)
	c1, c2 := m15Connection(t, a, gwA), m15Connection(t, a, gwA)
	a.mustExec(t, set, target, c1)
	a.want(t, m5Unique, "a second live connection with the target", set, target, c2)
	a.want(t, m5Check, "an empty target", set, "", c2)
	a.want(t, m5Check, "a target over 512 characters", set, "agentcore:"+strings.Repeat("a", 503), c2)
	a.mustExec(t, "UPDATE pc.connections SET state = 'RETIRED' WHERE id = $1", c1)
	a.mustExec(t, set, target, c2)

	gwB := m15Gateway(t, b)
	b.mustExec(t, set, target, m15Connection(t, b, gwB))
}

const m34Schedule = `INSERT INTO pc.saas_scan_schedules (org_id, source, connection_id, tenant, created_by)
	VALUES ($1, $2, $3, $4, 'user:alice')`

// TestTenancy_saas_scan_schedules: an org's daily scan schedules are
// invisible to and unchangeable by another org; source and tenant take only
// their shapes, one per (org, source, connection, tenant); pc_app may move
// only who started and when (D997a item 5), never re-key a schedule.
//
// Covers: F1046, HR-768
func TestTenancy_saas_scan_schedules(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	conn := m15Connection(t, a, m15Gateway(t, a))
	a.mustExec(t, m34Schedule, a.org, "aws_agentcore", conn, "123456789012")
	a.mustExec(t, m34Schedule, a.org, "vertex_agent_engine", conn, "my-project/us-central1")
	a.mustExec(t, m34Schedule, a.org, "azure_foundry", conn, "proj-1")

	a.want(t, m5Unique, "the same schedule twice", m34Schedule, a.org, "aws_agentcore", conn, "123456789012")
	a.want(t, m5Check, "an unknown source", m34Schedule, a.org, "github_scan", conn, "x")
	a.want(t, m5Check, "a tenant with a space", m34Schedule, a.org, "azure_foundry", conn, "a b")
	a.want(t, "23503", "a connection of no row", m34Schedule, a.org, "azure_foundry", m5ID(), "p")
	a.mustExec(t, `UPDATE pc.saas_scan_schedules SET last_started_at = now(), created_by = 'user:bob'
		WHERE source = 'aws_agentcore'`)
	a.want(t, m5Denied, "a schedule moved to another tenant",
		"UPDATE pc.saas_scan_schedules SET tenant = '210987654321' WHERE source = 'aws_agentcore'")
	a.want(t, m5Denied, "a schedule moved to another source",
		"UPDATE pc.saas_scan_schedules SET source = 'copilot_studio' WHERE source = 'azure_foundry'")

	if n := m10Count(t, p, b.org, "SELECT count(*) FROM pc.saas_scan_schedules"); n != 0 {
		t.Fatalf("another org sees %d schedules", n)
	}
	b.want(t, m5Check, "a schedule in another org (org write guard)", m34Schedule, a.org, "azure_foundry", conn, "proj-2")
	b.mustExec(t, "DELETE FROM pc.saas_scan_schedules")
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.saas_scan_schedules"); n != 3 {
		t.Fatalf("another org deleted schedules: %d left", n)
	}
	a.mustExec(t, "DELETE FROM pc.saas_scan_schedules WHERE source = 'azure_foundry'")
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.saas_scan_schedules"); n != 2 {
		t.Fatalf("after a person cleared one: %d", n)
	}
}

// TestHR768_00382AdmitsRuntimeSourcesAndTheScheduleOrigin: discoveries and
// scan runs admit the three runtime sources, a scan run the origin schedule
// with a connection (never without), and a Vertex tenant with a "/".
//
// Covers: F1045, F1046, HR-768
func TestHR768_00382AdmitsRuntimeSourcesAndTheScheduleOrigin(t *testing.T) {
	d := dbtest.New(t)
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	for _, c := range []struct{ table, constraint, value string }{
		{"pc.discoveries", "discoveries_source", "'aws_agentcore'"},
		{"pc.discoveries", "discoveries_source", "'vertex_agent_engine'"},
		{"pc.discoveries", "discoveries_source", "'azure_foundry'"},
		{"pc.discoveries", "discoveries_source_key", "'azure_foundry'"},
		{"pc.saas_scan_runs", "saas_scan_runs_source_check", "'aws_agentcore'"},
		{"pc.saas_scan_runs", "saas_scan_runs_origin_check", "'schedule'"},
		{"pc.saas_scan_runs", "saas_scan_runs_connection", "'schedule'"},
		{"pc.saas_scan_runs", "saas_scan_runs_tenant_check", "/"},
	} {
		var def string
		var valid bool
		if err := m.Pgx().QueryRow(ctx, `SELECT pg_get_constraintdef(oid), convalidated FROM pg_constraint
			WHERE conrelid = $1::regclass AND conname = $2`, c.table, c.constraint).Scan(&def, &valid); err != nil {
			t.Fatalf("%s %s: %v", c.table, c.constraint, err)
		}
		if !valid || !strings.Contains(def, c.value) {
			t.Errorf("%s %s (validated %v) does not admit %s: %s", c.table, c.constraint, valid, c.value, def)
		}
	}
	// The import origin still holds no connection; schedule and gateway do.
	var def string
	if err := m.Pgx().QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid = 'pc.saas_scan_runs'::regclass AND conname = 'saas_scan_runs_connection'`).Scan(&def); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(def, "'gateway'") || !strings.Contains(def, "connection_id IS NOT NULL") {
		t.Errorf("saas_scan_runs_connection: %s", def)
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check migrations 00321 and 00322 (G0 M28 D716, D719, D720).
// Names carry m28tm so that they never collide with other schema tests.

const m28tmSnapshot = `INSERT INTO pc.threat_map_snapshots (org_id, scope_key, framework, day, evaluated_at,
	catalog_version, catalog_digest, mapping_digest, states, counts)
	VALUES ($1, $2, $3, current_date, now(), '18.1', repeat('a', 64), repeat('b', 64), '{"T1059":"E P G N P"}', '{}')`

// TestTenancy_threat_map_snapshots: an org's snapshots are invisible to and
// unchangeable by another org; the scope key, framework and digests take
// only their shapes; one row per org, scope, framework and day; the job may
// replace a row's evaluation and delete it, never re-key it.
//
// Covers: F972, HR-686, HR-687
func TestTenancy_threat_map_snapshots(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	env := "env:" + m5ID()
	a.mustExec(t, m28tmSnapshot, a.org, "", "attack-enterprise")
	a.mustExec(t, m28tmSnapshot, a.org, env, "atlas")

	a.want(t, m5Unique, "the same day twice", m28tmSnapshot, a.org, "", "attack-enterprise")
	a.want(t, m5Check, "a scope key that is not an environment", m28tmSnapshot, a.org, "agent:"+m5ID(), "atlas")
	a.want(t, m5Check, "an unknown framework", m28tmSnapshot, a.org, "", "attack-mobile")
	a.want(t, m5Check, "a digest that is not sha256 hex",
		"UPDATE pc.threat_map_snapshots SET mapping_digest = 'x' WHERE scope_key = ''")
	a.want(t, m5Check, "states that are not an object",
		"UPDATE pc.threat_map_snapshots SET states = '[]' WHERE scope_key = ''")
	a.want(t, m5Denied, "a row re-keyed to another day",
		"UPDATE pc.threat_map_snapshots SET day = day - 1 WHERE scope_key = ''")
	a.want(t, m5Denied, "a row moved to another scope",
		"UPDATE pc.threat_map_snapshots SET scope_key = '' WHERE scope_key = $1", env)
	a.mustExec(t, `UPDATE pc.threat_map_snapshots SET states = '{"T1059":"G P G N G"}', evaluated_at = now()
		WHERE scope_key = ''`)

	if n := m10Count(t, p, b.org, "SELECT count(*) FROM pc.threat_map_snapshots"); n != 0 {
		t.Fatalf("another org sees %d snapshots", n)
	}
	b.want(t, m5Check, "a snapshot in another org (org write guard)", m28tmSnapshot, a.org, "", "atlas")
	b.mustExec(t, "DELETE FROM pc.threat_map_snapshots")
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.threat_map_snapshots"); n != 2 {
		t.Fatalf("another org deleted snapshots: %d left", n)
	}
	a.mustExec(t, "DELETE FROM pc.threat_map_snapshots WHERE scope_key = $1", env)
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.threat_map_snapshots"); n != 1 {
		t.Fatalf("after the job deleted one: %d", n)
	}
}

// TestM28_LastInputAndThreatMapPackScope: detection_rule_state takes a last
// input time, and an evidence pack may have scope threat_map (D716, D720).
//
// Covers: F968, HR-680
func TestM28_LastInputAndThreatMapPackScope(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a := newM5Fixture(t, p)
	a.mustExec(t, `INSERT INTO pc.detection_rule_state (org_id, rule_id, last_input_at) VALUES ($1, 'pc.x', now())`, a.org)
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.detection_rule_state WHERE last_input_at IS NOT NULL"); n != 1 {
		t.Fatal("last_input_at was not kept")
	}
	if n := m10Count(t, p, a.org, `SELECT count(*) FROM pg_constraint
		WHERE conname = 'evidence_packs_scope_kind_check' AND pg_get_constraintdef(oid) LIKE '%threat_map%'`); n != 1 {
		t.Fatal("evidence_packs_scope_kind_check does not admit threat_map")
	}
}

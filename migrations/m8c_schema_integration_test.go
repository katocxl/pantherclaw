// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check the schema's second line of defense for G0 M8 track C,
// connection tests (migration 00084): the application enforces the same
// rules first. Names are prefixed m8c so that they never collide with
// other milestones' schema tests in this package.

const m8cTest = `INSERT INTO pc.connection_tests (org_id, id, connection_id, result, checks, tested_by)
	VALUES ($1, $2, $3, $4, $5, 'test')`

// TestF354_ConnectionTestsAreKeptAsEvidence: pc_app records a test of one
// of its org's connections, with a result and a list of checks; it can
// neither change nor delete one.
func TestF354_ConnectionTestsAreKeptAsEvidence(t *testing.T) {
	d := dbtest.New(t)
	f := newM5Fixture(t, d.AppPool(t))
	gw, conn := m5ID(), m5ID()
	f.mustExec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", f.org, gw)
	f.mustExec(t, m6Connection, f.org, conn, "payments", "http", gw, "https://api.example.com", "none")
	f.mustExec(t, m8cTest, f.org, m5ID(), conn, "PASSED", `[{"check":"CONNECTION_ACTIVE","passed":true,"detail":"x"}]`)
	f.want(t, m5Check, "another result", m8cTest, f.org, m5ID(), conn, "MAYBE", `[]`)
	f.want(t, m5Check, "checks that are not a list", m8cTest, f.org, m5ID(), conn, "FAILED", `{}`)
	f.want(t, m7pForeignKey, "an unknown connection", m8cTest, f.org, m5ID(), m5ID(), "PASSED", `[]`)
	f.want(t, m5Denied, "UPDATE connection_tests", "UPDATE pc.connection_tests SET result = 'FAILED'")
	f.want(t, m5Denied, "DELETE connection_tests", "DELETE FROM pc.connection_tests")
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check migrations 00216 and 00217 (G0 M18 D151): another org
// neither reads nor changes an org's fleet policy or gateway alert state,
// and cannot write any in its name.

const m18Policy = `INSERT INTO pc.gateway_fleet_policy (org_id, minimum_version, silence_after_seconds, updated_by)
	VALUES ($1, 'v1.2.0', 600, 'test')`

// TestTenancy_gateway_fleet_policy: another org sees no fleet policy of an
// org, changes none, and cannot set one for it; the threshold stays within
// its bounds.
// Covers: PN-010.6
func TestTenancy_gateway_fleet_policy(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	a.mustExec(t, m18Policy, a.org)
	if n := m10Count(t, p, b.org, "SELECT count(*) FROM pc.gateway_fleet_policy"); n != 0 {
		t.Fatalf("another org sees %d policies", n)
	}
	b.mustExec(t, "UPDATE pc.gateway_fleet_policy SET minimum_version = NULL, silence_after_seconds = 86400")
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.gateway_fleet_policy WHERE minimum_version = 'v1.2.0' AND silence_after_seconds = 600"); n != 1 {
		t.Fatalf("another org changed the policy: %d left", n)
	}
	// The org write guard (00181) refuses it before row security would.
	b.want(t, "23514", "a policy in another org's name", m18Policy, a.org)
	b.want(t, "23514", "a threshold below 120 s", `INSERT INTO pc.gateway_fleet_policy (org_id, silence_after_seconds, updated_by)
		VALUES ($1, 119, 'test')`, b.org)
	b.want(t, "23514", "a threshold above a day", `INSERT INTO pc.gateway_fleet_policy (org_id, silence_after_seconds, updated_by)
		VALUES ($1, 86401, 'test')`, b.org)
}

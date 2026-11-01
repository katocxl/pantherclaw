// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR567_ManagedSettingsFindingsRaiseNoCoverage: a scan saying managed
// settings are present leaves every coverage table as it was, and its agent
// discovered. The attribute changing later moves nothing either, and a
// dismissed finding does not reopen for it (G0 M23 D114).
//
// Covers: F801, F852
func TestHR567_ManagedSettingsFindingsRaiseNoCoverage(t *testing.T) {
	w := newWorld(t)
	dev := as(w.org, td.KindServiceAccount, bind(td.RoleAgentOwner, td.ScopeOrg, w.org.UUID()))
	tables := []string{"coverage_snapshots", "coverage_closures", "coverage_routes", "coverage_invalidations"}
	count := func(sql string) int {
		t.Helper()
		var n int
		if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, sql).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := map[string]int{}
	for _, table := range tables {
		before[table] = count("SELECT count(*) FROM pc." + table)
	}
	found := func(state string) app.ScanFinding {
		f := server("tickets", "stdio")
		f.Attributes["managed_settings"] = state
		return f
	}
	for _, state := range []string{"not_found", "present", "conflict", "present"} {
		if _, err := w.inv.SubmitScan(dev, "laptop", []app.ScanFinding{found(state)}, app.ScanMode{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range tables {
		if n := count("SELECT count(*) FROM pc." + table); n != before[table] {
			t.Errorf("%s: %d rows, was %d", table, n, before[table])
		}
	}
	if n := count(`SELECT count(*) FROM pc.agents WHERE state <> 'DISCOVERED'`); n != 0 {
		t.Errorf("%d agents left DISCOVERED", n)
	}
	if n := count(`SELECT count(*) FROM pc.discoveries WHERE observed->>'managed_settings' = 'present'`); n != 1 {
		t.Errorf("%d discoveries hold the last state, want 1", n)
	}
	w.exec(t, w.org, `UPDATE pc.discoveries SET state = 'DISMISSED'`)
	if r, err := w.inv.SubmitScan(dev, "laptop", []app.ScanFinding{found("not_found")}, app.ScanMode{}); err != nil || r.Reopened != 0 {
		t.Fatalf("%+v %v: a change of managed state reopened a dismissed finding", r, err)
	}
}

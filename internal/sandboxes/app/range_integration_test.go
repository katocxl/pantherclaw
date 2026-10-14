// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/sandboxes/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR222_RoutesOfARangeSessionRecordNothing (D6): a session of a range
// agent, or one mapped to a simulated connection, reports routes without
// creating observed routes or route changes for coverage.
func TestHR222_RoutesOfARangeSessionRecordNothing(t *testing.T) {
	for name, flag := range map[string]string{
		"range agent":          "UPDATE pc.agents SET range_agent = true WHERE org_id = $1",
		"simulated connection": "UPDATE pc.connections SET simulated = true WHERE org_id = $1",
	} {
		w := newWorld(t)
		ctx := w.as(td.RoleAgentOwner)
		s, err := w.svc.StartSession(ctx, w.input())
		if err != nil {
			t.Fatal(err)
		}
		w.d.AdminExec(t, flag, w.org)
		routes := []app.Route{{Kind: "direct_api", Locator: "pypi.org:443"}}
		if n, err := w.svc.ReportRoutes(ctx, s.Session.ID, routes); err != nil || n != 0 {
			t.Fatalf("%s: %d new, %v, want none", name, n, err)
		}
		if n := w.count(t, "SELECT count(*) FROM pc.coverage_routes WHERE agent_id = $1", w.agent); n != 0 {
			t.Errorf("%s: %d routes stored", name, n)
		}
		if n := w.count(t, "SELECT count(*) FROM pc.coverage_invalidations WHERE agent_id = $1", w.agent); n != 0 {
			t.Errorf("%s: %d route changes", name, n)
		}
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/campaigns/adapters/pgcampaigns"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
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

// TestHR610_ARangeSessionsRoutesGoToItsOpenCampaignStep: a range agent's
// route report is stored on its open campaign step, the only source of a
// NOT_ROUTED_REPORTED outcome, and still nothing reaches coverage; with no
// open step nothing is stored (G0 M25 D525 L6).
// Covers: F903
func TestHR610_ARangeSessionsRoutesGoToItsOpenCampaignStep(t *testing.T) {
	w := newWorld(t)
	w.svc.Campaigns = pgcampaigns.Store{}
	ctx := w.as(td.RoleAgentOwner)
	s, err := w.svc.StartSession(ctx, w.input())
	if err != nil {
		t.Fatal(err)
	}
	w.d.AdminExec(t, "UPDATE pc.agents SET range_agent = true WHERE org_id = $1", w.org)
	routes := []app.Route{{Kind: "direct_api", Locator: "evil.example:443"}, {Kind: "credential", Locator: "github_token:abcd1234"}}
	if _, err := w.svc.ReportRoutes(ctx, s.Session.ID, routes); err != nil {
		t.Fatal(err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.campaign_routes WHERE org_id = $1", w.org); n != 0 {
		t.Fatalf("%d routes stored with no open campaign", n)
	}
	relay, campaign := ids.NewV7(), ids.NewV7()
	w.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, simulated, model_relay, created_by, updated_by)
		VALUES ($1, $2, 'relay', 'http', $3, 'model-relay', 'http://127.0.0.1:9', 'none', true, true, 'test', 'test')`, w.org, relay, w.gateway)
	w.exec(t, `INSERT INTO pc.campaigns (org_id, id, range_agent_id, started_by, runner_version, set_digest, scenario_ids, image_digest,
		model_host, relay_connection_id, scripted) VALUES ($1, $2, $3, 'user:x', 'test', $4, '{RT-140,RT-141}', $5, 'model.provider.test', $6, true)`,
		w.org, campaign, w.agent, strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), relay)
	if _, err := w.svc.ReportRoutes(ctx, s.Session.ID, routes); err != nil {
		t.Fatal(err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.campaign_routes WHERE org_id = $1", w.org); n != 0 {
		t.Fatalf("%d routes stored with no open step", n)
	}
	w.exec(t, "UPDATE pc.campaigns SET open_step = 'RT-141' WHERE org_id = $1 AND id = $2", w.org, campaign)
	if _, err := w.svc.ReportRoutes(ctx, s.Session.ID, routes); err != nil {
		t.Fatal(err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.campaign_routes WHERE org_id = $1 AND campaign_id = $2 AND scenario_id = 'RT-141'", w.org, campaign); n != 2 {
		t.Fatalf("%d routes on the open step, want 2", n)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.coverage_routes WHERE agent_id = $1", w.agent); n != 0 {
		t.Errorf("%d routes reached coverage", n)
	}
}

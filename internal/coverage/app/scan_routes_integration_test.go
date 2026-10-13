// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestF450_ScanFindingsAreObservedRoutesOfTheirConnection: an org-scan
// finding that names one of the org's connections becomes an observed route
// of every agent of it, once, until it is seen again; a finding naming no
// connection of the org, or showing no route, is left out, and so is one
// whose scan run is not a scan of the connection it names (a workflow
// shows one when it writes, deploys or runs on default permissions); a route no
// source showed stays "not observed" in the record. Findings that
// show no route never hold back the ones after them, however many there
// are.
func TestF450_ScanFindingsAreObservedRoutesOfTheirConnection(t *testing.T) {
	f := newFixture(t)
	finding := func(observed string) {
		agent := ids.NewV7()
		f.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'found', 'DISCOVERED', 'test')", f.org, agent)
		key := make([]byte, 32)
		copy(key, agent[:])
		f.exec(t, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key, observed) VALUES ($1, $2, $3, 'github_scan', $4, $5)`,
			f.org, ids.NewV7(), agent, key, []byte(observed))
	}
	conn := f.conn.String()
	// Every finding names the scan run of the connection that found it.
	run := ids.NewV7().String()
	f.exec(t, `INSERT INTO pc.github_scan_runs (org_id, id, connection_id, state, started_by, finished_at)
		VALUES ($1, $2, $3, 'DONE', 'test', now())`, f.org, run, f.conn)
	// More findings that show no route than one refresh reads, before the
	// ones that do.
	skippable := make([]string, 201)
	for i := range skippable {
		skippable[i] = ids.NewV7().String()
	}
	f.exec(t, `INSERT INTO pc.agents (org_id, id, name, state, created_by)
		SELECT $1, a, 'found', 'DISCOVERED', 'test' FROM unnest($2::uuid[]) AS a`, f.org, skippable)
	f.exec(t, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key, observed)
		SELECT $1, a, a, 'github_scan', sha256(convert_to(a::text, 'UTF8')), $3 FROM unnest($2::uuid[]) AS a`, f.org, skippable,
		[]byte(`{"kind": "github_workflow", "connection": "`+conn+`", "scan_run": "`+run+`", "repo": "acme/app", "path": ".github/workflows/lint.yml"}`))
	finding(`{"kind": "github_mcp_config", "connection": "` + conn + `", "scan_run": "` + run + `", "repo": "acme/app", "path": ".mcp.json"}`)
	finding(`{"kind": "github_workflow", "connection": "` + conn + `", "scan_run": "` + run + `", "repo": "acme/app", "path": ".github/workflows/deploy.yml", "deploys": "true"}`)
	// A job on the repository's default permissions may write.
	finding(`{"kind": "github_workflow", "connection": "` + conn + `", "scan_run": "` + run + `", "repo": "acme/app", "path": ".github/workflows/agent.yml", "writes": "false", "deploys": "false", "permissions_default": "true"}`)
	finding(`{"kind": "github_workflow", "connection": "` + conn + `", "scan_run": "` + run + `", "repo": "acme/app", "path": ".github/workflows/lint.yml"}`)
	finding(`{"kind": "github_app", "connection": "` + ids.NewV7().String() + `", "app_slug": "elsewhere"}`)
	// A finding whose scan run is not a scan of the connection it names shows
	// no route there.
	finding(`{"kind": "github_mcp_config", "connection": "` + conn + `", "scan_run": "` + ids.NewV7().String() + `", "repo": "acme/other", "path": ".mcp.json"}`)
	finding(`{"kind": "mcp_server", "name": "local"}`)
	// A dismissed discovery still shows its route.
	finding(`{"kind": "github_app", "connection": "` + conn + `", "scan_run": "` + run + `", "app_slug": "dismissed"}`)
	f.exec(t, `UPDATE pc.discoveries SET state = 'DISMISSED' WHERE observed ->> 'app_slug' = 'dismissed'`)
	// A person's pclaw scan (source scan) cannot report a GitHub org-scan
	// kind: it shows no route (N20).
	gh := ids.NewV7()
	f.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'found', 'DISCOVERED', 'test')", f.org, gh)
	f.exec(t, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key, observed) VALUES ($1, $2, $3, 'scan', $4, $5)`,
		f.org, ids.NewV7(), gh, make([]byte, 32), []byte(`{"kind": "github_mcp_config", "connection": "`+conn+`", "scan_run": "`+run+`", "repo": "acme/web", "path": ".mcp.json"}`))
	refresh := func() []ids.UUID {
		var touched []ids.UUID
		if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			touched, err = f.svc.RefreshScanRoutes(ctx, tx)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return touched
	}
	if touched := refresh(); len(touched) != 1 || touched[0] != f.conn {
		t.Fatalf("touched %v", touched)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.coverage_routes WHERE source = 'scan' AND agent_id IS NULL AND observation = 'observed'`); n != 4 {
		t.Fatalf("%d scan routes, want the MCP configuration, the deploying workflow, the one on default permissions and the dismissed app", n)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.coverage_invalidations WHERE kind = 'route' AND detail LIKE '%org scan'`); n != 4 {
		t.Fatalf("%d route changes, want one per new scan route", n)
	}
	if touched := refresh(); len(touched) != 0 {
		t.Fatalf("an unchanged scan recorded again: %v", touched)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.coverage_routes WHERE kind = $1 AND locator = 'acme/app .mcp.json'`,
		string(domain.KindDirectAPI)); n != 1 {
		t.Fatalf("%d direct API routes from the MCP configuration", n)
	}
}

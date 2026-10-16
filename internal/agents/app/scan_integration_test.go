// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"crypto/sha256"
	"testing"

	"github.com/katocxl/pantherclaw/internal/agents/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func finding(kind, name string) app.ScanFinding {
	return app.ScanFinding{Kind: kind, Key: sha256.Sum256([]byte(kind + name)), Attributes: map[string]string{"name": name, "client": "cursor"}}
}

// TestF015_ScanFindingsBecomeDiscoveredAgents (PN-001.1): submitted
// findings become DISCOVERED agents with ADMISSION entries and untrusted
// observations; a resubmission is only counted; the open cap holds.
func TestF015_ScanFindingsBecomeDiscoveredAgents(t *testing.T) {
	w := newWorld(t)
	fs := []app.ScanFinding{finding("mcp_server", "github"), finding("agent_project", "/src/bot")}
	_, err := w.inv.SubmitScan(as(w.org, td.KindUser, bind(td.RoleViewer, td.ScopeOrg, w.org.UUID())), "laptop", fs)
	wantCode(t, "without agent.manage", err, pcerr.PermissionDenied, "")
	r, err := w.inv.SubmitScan(w.teamOwner(), "laptop", fs)
	if err != nil || r.Created != 2 || r.Counted != 0 {
		t.Fatalf("first submission: %+v, %v", r, err)
	}
	if n := w.count(t, `SELECT count(*) FROM pc.agents a JOIN pc.discoveries d ON d.org_id = a.org_id AND d.agent_id = a.id
		JOIN pc.waitlist_entries e ON e.org_id = a.org_id AND e.subject_id = a.id AND e.subject_type = 'agent'
		WHERE a.org_id = $1 AND a.state = 'DISCOVERED' AND d.source = 'scan' AND d.observed->>'host' = 'laptop'
		  AND e.evidence->'untrusted'->>'client' = 'cursor'`, w.org); n != 2 {
		t.Fatalf("discovered agents with entries: %d", n)
	}
	// Each discovery is an audit record too, so it reaches the evidence feed
	// (the agent.discovered automation trigger, G0 M11 part 2 D18a).
	if n := w.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.agent.discovered'
		AND convert_from(body, 'UTF8')::jsonb #>> '{details,source}' = 'scan'`, w.org); n != 2 {
		t.Fatalf("agent.discovered audit records: %d", n)
	}
	r, err = w.inv.SubmitScan(w.teamOwner(), "laptop", fs)
	if err != nil || r.Created != 0 || r.Counted != 2 || w.count(t, "SELECT max(seen_count) FROM pc.discoveries WHERE org_id = $1", w.org) != 2 {
		t.Fatalf("resubmission: %+v, %v", r, err)
	}
	w.exec(t, w.org, `WITH a AS (INSERT INTO pc.agents (org_id, id, name, state, created_by)
		SELECT $1, gen_random_uuid(), 'd' || g, 'DISCOVERED', 'test' FROM generate_series(1, $2::int) g RETURNING id)
		INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key)
		SELECT $1, gen_random_uuid(), id, 'scan', sha256(id::text::bytea) FROM a`, w.org, app.MaxOpenScanDiscoveries)
	r, err = w.inv.SubmitScan(w.teamOwner(), "laptop", []app.ScanFinding{finding("mcp_server", "new")})
	if err != nil || r.Dropped != 1 || r.Created != 0 {
		t.Fatalf("over the cap: %+v, %v", r, err)
	}
}

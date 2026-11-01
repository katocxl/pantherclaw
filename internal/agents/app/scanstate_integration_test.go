// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestF832_AnAgentsScanStateSumsItsFindings: an agent no scan found has no
// state; otherwise a finding one scan still sees keeps it from vanishing, and
// a dismissed finding does not count. Get and List agree.
//
// Covers: F832
func TestF832_AnAgentsScanStateSumsItsFindings(t *testing.T) {
	w := newWorld(t)
	reader := as(w.org, td.KindUser, bind(td.RoleOrgAdmin, td.ScopeOrg, w.org.UUID()))
	if _, err := w.inv.SubmitScan(w.teamOwner(), "laptop", []app.ScanFinding{finding("mcp_server", "github")}, app.ScanMode{}); err != nil {
		t.Fatal(err)
	}
	plain := ids.NewV7()
	w.exec(t, w.org, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'plain', 'DISCOVERED', 'test')", w.org, plain)

	byID := func() map[ids.UUID]app.Agent {
		t.Helper()
		got, _, err := w.inv.List(reader, page.Request{Size: 10}, nil, ids.UUID{})
		if err != nil || len(got.Items) != 2 {
			t.Fatalf("list: %+v, %v", got, err)
		}
		out := map[ids.UUID]app.Agent{}
		for _, a := range got.Items {
			out[a.ID] = a
		}
		return out
	}
	agents := byID()
	if agents[plain].ScanState != nil {
		t.Fatalf("no scan found it: %+v", agents[plain].ScanState)
	}
	delete(agents, plain)
	var found ids.UUID
	for id, a := range agents {
		found = id
		if s := a.ScanState; s == nil || s.MissedScans != 0 || s.Vanished || s.LastSeenAt.IsZero() {
			t.Fatalf("a fresh finding: %+v", s)
		}
	}

	want := func(step string, missed int32, vanished bool) {
		t.Helper()
		sum, err := w.inv.Get(reader, found)
		if err != nil {
			t.Fatal(err)
		}
		listed := byID()[found].ScanState
		for name, s := range map[string]*app.ScanState{"get": sum.Agent.ScanState, "list": listed} {
			if s == nil || s.MissedScans != missed || s.Vanished != vanished {
				t.Fatalf("%s, %s: %+v, want %d missed, vanished %v", step, name, s, missed, vanished)
			}
		}
	}

	w.exec(t, w.org, "UPDATE pc.discoveries SET missed_scans = 3, vanish_notified_at = now() WHERE org_id = $1", w.org)
	want("vanished", 3, true)

	other := ids.NewV7()
	w.exec(t, w.org, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key)
		VALUES ($1, $2, $3, 'scan', sha256('other'::bytea))`, w.org, other, found)
	want("seen by another finding", 0, false)

	w.exec(t, w.org, "UPDATE pc.discoveries SET state = 'DISMISSED' WHERE org_id = $1 AND id = $2", w.org, other)
	want("that finding dismissed", 3, true)
}

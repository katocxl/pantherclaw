// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package search

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR684_SearchFiltersAlertsAndIncidentsByTechnique: the technique
// filter matches an ATLAS or ATT&CK id exactly or as the parent of a
// sub-technique, within the viewer's scope, and counts the same (G0 M28
// D726). Covers: F964, HR-684
func TestHR684_SearchFiltersAlertsAndIncidentsByTechnique(t *testing.T) {
	f := newM11Fx(t)
	f.exec(`INSERT INTO pc.alerts (org_id, id, source, title, severity, attention, basis, subjects, dedupe_key,
		first_seen, last_seen, atlas, attack) VALUES ($1, $2, 'detection', 'Mapped', 'HIGH', 'ALERT', 'RULE_MATCH',
		jsonb_build_array(jsonb_build_object('type', 'agent', 'id', $3::text)), $4, now(), now(),
		'{AML.T0051.000}', '{T1552.001}')`, f.org, ids.NewV7(), f.agentA.String(), ids.NewV7().String())
	f.exec(`UPDATE pc.incidents SET atlas = '{AML.T0024}', attack = '{T1078}' WHERE org_id = $1 AND id = $2`, f.org, f.incidentB)

	for _, c := range []struct {
		entity    Entity
		technique string
		want      int
	}{
		{EntityAlerts, "T1552.001", 1},
		{EntityAlerts, "T1552", 1},
		{EntityAlerts, "AML.T0051", 1},
		{EntityAlerts, "T1552.002", 0},
		{EntityIncidents, "AML.T0024", 1},
		{EntityIncidents, "T1078", 1},
		{EntityIncidents, "T1552", 0},
	} {
		r := f.search(f.auditor, Query{Entity: c.entity, Filters: Filters{Technique: c.technique}})
		if r.Count != c.want || len(r.Items) != c.want {
			t.Errorf("%s %s: count %d, %d items, want %d", c.entity, c.technique, r.Count, len(r.Items), c.want)
		}
	}
	// incidentB is about agent B, which the team-A responder does not see.
	if r := f.search(f.responder, Query{Entity: EntityIncidents, Filters: Filters{Technique: "T1078"}}); r.Count != 0 {
		t.Errorf("hidden incident counted: %+v", r)
	}
}

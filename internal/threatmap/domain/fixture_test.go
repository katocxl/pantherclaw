// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapping"
)

// now is the evaluation time of every fixture.
var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

// fixtureCatalog is a small ATT&CK-like catalog: two tactics, T0001 under
// both, T0002 with two sub-techniques, T0003 outside, T0004 unaddressed.
func fixtureCatalog() *catalog.Catalog {
	return &catalog.Catalog{
		Framework: catalog.FrameworkATTACK, Version: "20.0", Digest: "c0",
		Tactics: []catalog.Tactic{
			{ID: "TA0002", ShortName: "execution", Name: "Execution", Order: 1},
			{ID: "TA0010", ShortName: "exfiltration", Name: "Exfiltration", Order: 2},
		},
		Techniques: []catalog.Technique{
			{ID: "T0001", Name: "Alpha", Tactics: []string{"execution", "exfiltration"}},
			{ID: "T0002", Name: "Beta", Tactics: []string{"execution"}},
			{ID: "T0002.001", Name: "Beta one", Tactics: []string{"execution"}, Parent: "T0002"},
			{ID: "T0002.002", Name: "Beta two", Tactics: []string{"execution"}, Parent: "T0002"},
			{ID: "T0003", Name: "Gamma", Tactics: []string{"exfiltration"}},
			{ID: "T0003.001", Name: "Gamma one", Tactics: []string{"exfiltration"}, Parent: "T0003"},
			{ID: "T0004", Name: "Delta", Tactics: []string{"exfiltration"}},
			{ID: "T0005", Name: "Old", Tactics: []string{"execution"}, Deprecated: true},
		},
	}
}

// fixtureMapping maps T0001 on every lane, T0002.001 on Prevent only, T0003
// outside and T0004 unaddressed.
func fixtureMapping() domain.Mapping {
	return domain.Mapping{
		Digest: "m0",
		Techniques: map[string]domain.TechniqueMap{
			"T0001": {
				Prevent: []string{"prevent.a"}, Rules: []string{"pc.rule.a"}, Scenarios: []string{"RT-001"},
				Campaigns: []string{"CA-001"}, HubPlaybooks: []string{"pc.respond.a"},
			},
			"T0002.001": {Prevent: []string{"prevent.a"}},
			"T0003":     {Outside: &mapping.OutsideEntry{ID: "T0003", Reason: mapping.OutsideEndpoint, CoveredBy: mapping.ToolEDR}},
			"T0004":     {Unaddressed: &mapping.UnaddressedEntry{ID: "T0004", Why: "Delta (T0004): no control."}},
		},
		Controls: []mapping.PreventControl{
			{
				ID: "prevent.a", Title: "Grants", Surface: mapping.SurfaceAuthority, ReasonCodes: []string{"NO_GRANT"},
				HR: []string{"HR-045"}, Requires: mapping.RequiresAlways, Techniques: []string{"T0001", "T0002.001"},
				Why: map[string]string{"T0001": "Grants refuse it (T0001).", "T0002.001": "Grants refuse it (T0002.001)."},
			},
			{
				ID: "prevent.content", Title: "Content hold", Surface: mapping.SurfaceGateway, ReasonCodes: []string{"CONTENT_HOLD"},
				HR: []string{"HR-647"}, Requires: mapping.RequiresContentSignalsActive, Techniques: []string{"T0001"},
			},
		},
		Builtins: map[string]domain.BuiltinRule{
			"pc.rule.a": {Title: "Rule A", Inputs: []string{"transaction.decided"}},
			"pc.rule.b": {Title: "Rule B", Business: true, Inputs: []string{"audit.security.x"}},
		},
		Scenarios:        map[string]domain.Scenario{"RT-001": {Digest: "d1", Why: map[string]string{"T0001": "Tests it (T0001)."}}},
		HubPlaybookRules: map[string][]string{"pc.respond.a": {"pc.rule.a"}},
	}
}

// business is an org with every edition feature, one agent with fresh
// enforced routes, a live rule, an active automation and a passed test.
func business() domain.Inputs {
	return domain.Inputs{
		Framework: catalog.FrameworkATTACK, EvaluatedAt: now,
		Editions: domain.Editions{
			AdvancedDetections: true, CustomDetections: true, BehaviorAnalytics: true, ContentSignals: true,
			Automations: true, AutomationPlaybooks: true,
		},
		ContentMode: "ACTIVE",
		Agents: []domain.Agent{
			{ID: "a1", Name: "builder", EnvironmentID: "e1", Active: true, LastRealTransaction: now.Add(-time.Hour)},
		},
		Routes: []domain.Route{{AgentID: "a1", ConnectionID: "c1", Operation: "github.pulls.merge", State: "ENFORCED", ExpiresAt: now.Add(time.Hour)}},
		Rules: []domain.Rule{
			{ID: "pc.rule.a", Title: "Rule A", Source: domain.SourceBuiltin, Published: true, LastInputAt: now.Add(-time.Hour), Inputs: []string{"transaction.decided"}},
		},
		Cursor:      domain.Cursor{CaughtUp: true, AdvancedAt: now.Add(-time.Minute)},
		Automations: []domain.Automation{{ID: "au1", Name: "contain-a", State: "ACTIVE", TriggerRules: []string{"pc.rule.a"}}},
		Results: []domain.Result{
			{ScenarioID: "RT-001", RangeID: "r1", Digest: "d1", Verdict: "PASS", ObservedBy: "SERVER", RecordedAt: now.Add(-24 * time.Hour)},
		},
		Alerts:    []domain.AlertGroup{{Techniques: []string{"T0001"}, Count: 3}, {Techniques: []string{"T0002.001"}, Count: 2}},
		Decisions: []domain.DecisionCount{{ReasonCode: "NO_GRANT", Decision: "DENY", Count: 5}, {ReasonCode: "NO_GRANT", Decision: "REQUIRE_APPROVAL", Count: 1}, {ReasonCode: "OTHER", Decision: "DENY", Count: 9}},
	}
}

func technique(t *testing.T, m domain.Map, id string) domain.Technique {
	t.Helper()
	tech, ok := m.Technique(id)
	if !ok {
		t.Fatalf("no technique %s", id)
	}
	return tech
}

func eval(in domain.Inputs) domain.Map {
	return domain.Evaluate(fixtureCatalog(), fixtureMapping(), in)
}

func hasReason(rs []domain.Reason, r domain.Reason) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

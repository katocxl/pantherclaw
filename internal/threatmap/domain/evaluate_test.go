// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
)

// TestHR680_PreventLaneFromRoutes: Prevent reads the mapped controls and
// the latest route records of the active agents in scope; a stale ENFORCED
// record reads PARTIAL and the fix names the agents (G0 M28 D713).
// Covers: F960, F962, F963, HR-680
func TestHR680_PreventLaneFromRoutes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(*domain.Inputs)
		state  domain.LaneState
		reason domain.Reason
		fix    string
	}{
		{"all enforced", func(*domain.Inputs) {}, domain.LaneEvidenced, "", ""},
		{"no agents", func(in *domain.Inputs) { in.Agents = nil }, domain.LaneGap, domain.ReasonNoRoutes, "Route your agents"},
		{"agent without a record", func(in *domain.Inputs) { in.Routes = nil }, domain.LaneGap, domain.ReasonNoEnforcedRoute, "builder"},
		{"stale enforced", func(in *domain.Inputs) { in.Routes[0].ExpiresAt = now.Add(-time.Minute) }, domain.LaneGap, domain.ReasonNoEnforcedRoute, "builder"},
		{"some enforced", func(in *domain.Inputs) {
			in.Agents = append(in.Agents, domain.Agent{ID: "a2", Name: "reviewer", Active: true})
			in.Routes = append(in.Routes, domain.Route{AgentID: "a2", ConnectionID: "c1", Operation: "x.y", State: "OBSERVE_ONLY"})
		}, domain.LanePartial, domain.ReasonRoutesNotEnforced, "reviewer"},
		{"inactive agents do not count", func(in *domain.Inputs) {
			in.Agents = append(in.Agents, domain.Agent{ID: "a2", Name: "retired", Active: false})
		}, domain.LaneEvidenced, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := business()
			tc.edit(&in)
			tech := technique(t, eval(in), "T0001")
			if tech.Prevent.State != tc.state || (tc.reason != "" && !hasReason(tech.Prevent.Reasons, tc.reason)) {
				t.Fatalf("prevent %s %v, want %s %s", tech.Prevent.State, tech.Prevent.Reasons, tc.state, tc.reason)
			}
			if tc.fix == "" {
				return
			}
			for _, g := range tech.Gaps {
				if g.Lane == domain.LanePrevent && g.Fix.Kind == domain.FixRouteThroughGateway && strings.Contains(g.Fix.Label, tc.fix) {
					return
				}
			}
			t.Errorf("no route fix naming %q in %+v", tc.fix, tech.Gaps)
		})
	}
}

// TestHR680_PreventControlOffAndScope: a control whose requirement does not
// hold is CONTROL_OFF with its setting as the fix; the environment filter
// narrows the routes, and route counts are always shown.
// Covers: F962, F963, HR-680
func TestHR680_PreventControlOffAndScope(t *testing.T) {
	m := fixtureMapping()
	m.Controls = m.Controls[1:] // only the content control
	m.Techniques["T0001"] = domain.TechniqueMap{Prevent: []string{"prevent.content"}}
	in := business()
	in.ContentMode = "WATCHING"
	tech := technique(t, domain.Evaluate(fixtureCatalog(), m, in), "T0001")
	if tech.Prevent.State != domain.LaneGap || tech.Prevent.Reasons[0] != domain.ReasonControlOff {
		t.Fatalf("prevent %+v", tech.Prevent)
	}
	if tech.Gaps[0].Fix.Kind != domain.FixTurnOnSetting || tech.Gaps[0].Fix.TargetID != "content_signals" {
		t.Errorf("fix %+v", tech.Gaps[0].Fix)
	}

	in = business()
	in.Agents = append(in.Agents, domain.Agent{ID: "a2", Name: "other", EnvironmentID: "e2", Active: true})
	in.Scope = domain.Scope{EnvironmentID: "e1"}
	mp := eval(in)
	if p := technique(t, mp, "T0001").Prevent; p.State != domain.LaneEvidenced || p.Routes.Enforced != 1 || p.Routes.Unknown != 0 {
		t.Errorf("environment e1: %+v", p)
	}
	in.Scope = domain.Scope{EnvironmentID: "e2"}
	if p := technique(t, eval(in), "T0001").Prevent; p.State != domain.LaneGap || p.Routes.Unknown != 1 {
		t.Errorf("environment e2: %+v", p)
	}
	in.Scope = domain.Scope{AgentID: "a1"}
	if p := technique(t, eval(in), "T0001").Prevent; p.State != domain.LaneEvidenced {
		t.Errorf("agent a1: %+v", p)
	}
	if len(mp.OrgWide) != 3 || mp.OrgWide[0] != domain.LaneDetect {
		t.Errorf("org-wide lanes %v", mp.OrgWide)
	}
}

// TestHR680_DetectLaneStates: every Detect reason (D713).
// Covers: F960, F962, HR-680, HR-685
func TestHR680_DetectLaneStates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(*domain.Inputs, *domain.Mapping)
		state  domain.LaneState
		reason domain.Reason
		fix    domain.FixKind
	}{
		{"input recent", func(*domain.Inputs, *domain.Mapping) {}, domain.LaneEvidenced, "", ""},
		{"not licensed", func(in *domain.Inputs, m *domain.Mapping) {
			b := m.Builtins["pc.rule.a"]
			b.Business = true
			m.Builtins["pc.rule.a"] = b
			in.Editions.AdvancedDetections = false
		}, domain.LanePartial, domain.ReasonEditionRequired, domain.FixUpgradeEdition},
		{"auto-disabled", func(in *domain.Inputs, _ *domain.Mapping) { in.Rules[0].Disabled = true }, domain.LaneGap, domain.ReasonRuleOff, domain.FixEnableRule},
		{"suppressed", func(in *domain.Inputs, _ *domain.Mapping) { in.Rules[0].Suppressed = true }, domain.LanePartial, domain.ReasonRuleSuppressed, domain.FixEndSuppression},
		{"silent", func(in *domain.Inputs, _ *domain.Mapping) { in.Rules[0].LastInputAt = now.Add(-8 * 24 * time.Hour) }, domain.LanePartial, domain.ReasonRuleSilent, domain.FixSendEvents},
		{"audit-only rule, engine live", func(in *domain.Inputs, m *domain.Mapping) {
			m.Techniques["T0001"] = domain.TechniqueMap{Rules: []string{"pc.rule.b"}}
			in.Rules = []domain.Rule{{ID: "pc.rule.b", Source: domain.SourceBuiltin, Published: true}}
		}, domain.LaneEvidenced, "", ""},
		{"audit-only rule, engine behind", func(in *domain.Inputs, m *domain.Mapping) {
			m.Techniques["T0001"] = domain.TechniqueMap{Rules: []string{"pc.rule.b"}}
			in.Rules = []domain.Rule{{ID: "pc.rule.b", Source: domain.SourceBuiltin, Published: true}}
			in.Cursor.AdvancedAt = now.Add(-25 * time.Hour)
		}, domain.LanePartial, domain.ReasonRuleSilent, domain.FixSendEvents},
		{"hub rule installed and published", func(in *domain.Inputs, m *domain.Mapping) {
			m.Techniques["T0001"] = domain.TechniqueMap{HubRules: []string{"org.hub.x"}}
			in.Rules = []domain.Rule{{ID: "org.hub.x", Source: domain.SourceHub, Published: true, LastInputAt: now, Inputs: []string{"k"}}}
		}, domain.LaneEvidenced, "", ""},
		{"hub rule changed by the org reads as stated", func(in *domain.Inputs, m *domain.Mapping) {
			m.Techniques["T0001"] = domain.TechniqueMap{HubRules: []string{"org.hub.x"}}
			in.Rules = []domain.Rule{{ID: "org.hub.x", Source: domain.SourceCustom, Published: true, LastInputAt: now, Techniques: []string{"T0001"}}}
		}, domain.LaneStated, domain.ReasonStated, ""},
		{"hub rule not installed", func(in *domain.Inputs, m *domain.Mapping) {
			m.Techniques["T0001"] = domain.TechniqueMap{HubRules: []string{"org.hub.x"}}
			in.Rules = nil
		}, domain.LaneNoneShipped, domain.ReasonNoneShipped, ""},
		{"content kind, mode off", func(in *domain.Inputs, m *domain.Mapping) {
			m.Techniques["T0001"] = domain.TechniqueMap{Kinds: []string{"content.injection_phrase"}}
			in.ContentMode = "OFF"
		}, domain.LaneGap, domain.ReasonRuleOff, domain.FixTurnOnSetting},
		{"behavior kind, not licensed", func(in *domain.Inputs, m *domain.Mapping) {
			m.Techniques["T0001"] = domain.TechniqueMap{Kinds: []string{"behavior.NEW_TOOL"}}
			in.Editions.BehaviorAnalytics = false
		}, domain.LanePartial, domain.ReasonEditionRequired, domain.FixUpgradeEdition},
		{"behavior kind, no recent transaction", func(in *domain.Inputs, m *domain.Mapping) {
			m.Techniques["T0001"] = domain.TechniqueMap{Kinds: []string{"behavior.NEW_TOOL"}}
			in.Agents[0].LastRealTransaction = now.Add(-8 * 24 * time.Hour)
		}, domain.LanePartial, domain.ReasonRuleSilent, domain.FixSendEvents},
		{"behavior kind, live", func(_ *domain.Inputs, m *domain.Mapping) {
			m.Techniques["T0001"] = domain.TechniqueMap{Kinds: []string{"behavior.NEW_TOOL"}}
		}, domain.LaneEvidenced, "", ""},
		{"nothing mapped", func(in *domain.Inputs, m *domain.Mapping) {
			m.Techniques["T0001"] = domain.TechniqueMap{Prevent: []string{"prevent.a"}}
		}, domain.LaneNoneShipped, domain.ReasonNoneShipped, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, m := business(), fixtureMapping()
			tc.edit(&in, &m)
			tech := technique(t, domain.Evaluate(fixtureCatalog(), m, in), "T0001")
			d := tech.Detect
			if d.State != tc.state || (tc.reason != "" && !hasReason(d.Reasons, tc.reason)) {
				t.Fatalf("detect %s %v, want %s %s", d.State, d.Reasons, tc.state, tc.reason)
			}
			if tc.fix == "" {
				return
			}
			for _, g := range tech.Gaps {
				if g.Lane == domain.LaneDetect && g.Fix.Kind == tc.fix {
					return
				}
			}
			t.Errorf("no %s fix in %+v", tc.fix, tech.Gaps)
		})
	}
}

// TestHR685_OwnRulesAreStatedNeverEvidence: an org's own published rule
// mapped to a technique makes Detect STATED at most and is listed as the
// org's; it never raises the status (G0 M28 D713).
// Covers: F960, HR-685, T-301
func TestHR685_OwnRulesAreStatedNeverEvidence(t *testing.T) {
	in, m := business(), fixtureMapping()
	m.Techniques["T0001"] = domain.TechniqueMap{}
	in.Rules = []domain.Rule{{ID: "org.mine", Source: domain.SourceCustom, Published: true, LastInputAt: now, Techniques: []string{"T0001"}}}
	in.Automations = []domain.Automation{{ID: "au1", Name: "mine", State: "ACTIVE", TriggerRules: []string{"org.mine"}}}
	tech := technique(t, domain.Evaluate(fixtureCatalog(), m, in), "T0001")
	if tech.Detect.State != domain.LaneStated || tech.Detect.Rules[0].Source != domain.SourceCustom {
		t.Errorf("detect %+v", tech.Detect)
	}
	if tech.Respond.State != domain.LaneStated {
		t.Errorf("respond %+v", tech.Respond)
	}
	if tech.Status != domain.StatusGap {
		t.Errorf("status %s: stated lanes raised it", tech.Status)
	}
	in.Rules[0].Published = false
	if d := technique(t, domain.Evaluate(fixtureCatalog(), m, in), "T0001").Detect; d.State != domain.LaneNoneShipped {
		t.Errorf("an unpublished own rule: %+v", d)
	}
}

// TestHR680_RespondLaneStates: every Respond reason (D713).
// Covers: F960, F962, HR-680
func TestHR680_RespondLaneStates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(*domain.Inputs)
		state  domain.LaneState
		reason domain.Reason
		fix    domain.FixKind
	}{
		{"active", func(*domain.Inputs) {}, domain.LaneEvidenced, "", ""},
		{"community", func(in *domain.Inputs) { in.Editions = domain.Editions{} }, domain.LaneGap, domain.ReasonEditionRequired, domain.FixUpgradeEdition},
		{"trigger rule off", func(in *domain.Inputs) { in.Rules[0].Disabled = true }, domain.LanePartial, domain.ReasonTriggerRuleOff, domain.FixEnableRule},
		{"paused", func(in *domain.Inputs) { in.Automations[0].State = "PAUSED" }, domain.LanePartial, domain.ReasonPlaybookDisabled, domain.FixEnablePlaybook},
		// D720a(3): a DRAFT automation only names its fix.
		{"draft", func(in *domain.Inputs) { in.Automations[0].State = "DRAFT" }, domain.LaneGap, domain.ReasonPlaybookDisabled, domain.FixEnablePlaybook},
		{"contain without playbooks", func(in *domain.Inputs) {
			in.Automations[0].HasContain = true
			in.Editions.AutomationPlaybooks = false
		}, domain.LanePartial, domain.ReasonEditionRequired, domain.FixUpgradeEdition},
		{"hub playbook not installed", func(in *domain.Inputs) { in.Automations = nil }, domain.LaneGap, domain.ReasonPlaybookNotInstalled, domain.FixInstallHubItem},
		{"other trigger", func(in *domain.Inputs) {
			in.Automations[0].TriggerRules = []string{"pc.other"}
		}, domain.LaneGap, domain.ReasonPlaybookNotInstalled, domain.FixInstallHubItem},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := business()
			tc.edit(&in)
			tech := technique(t, eval(in), "T0001")
			r := tech.Respond
			if r.State != tc.state || (tc.reason != "" && !hasReason(r.Reasons, tc.reason)) {
				t.Fatalf("respond %s %v, want %s %s", r.State, r.Reasons, tc.state, tc.reason)
			}
			if tc.fix == "" {
				return
			}
			for _, g := range tech.Gaps {
				if g.Lane == domain.LaneRespond && g.Fix.Kind == tc.fix {
					return
				}
			}
			t.Errorf("no %s fix in %+v", tc.fix, tech.Gaps)
		})
	}
	m := fixtureMapping()
	m.Techniques["T0001"] = domain.TechniqueMap{Prevent: []string{"prevent.a"}}
	if r := technique(t, domain.Evaluate(fixtureCatalog(), m, business()), "T0001").Respond; r.State != domain.LaneNoneShipped {
		t.Errorf("nothing mapped: %+v", r)
	}
}

// TestHR680_DraftAutomationNeverMakesRespondMoreThanGap: a DRAFT automation
// triggered by a mapped rule names its ENABLE_PLAYBOOK fix and leaves
// Respond GAP, so with Prevent and Detect not working the technique stays
// GAP; only an ACTIVE automation counts (G0 M28 D720a(3)).
// Covers: F960, F962, HR-680
func TestHR680_DraftAutomationNeverMakesRespondMoreThanGap(t *testing.T) {
	in := business()
	in.Automations[0].State = "DRAFT"
	in.Routes = nil
	in.Rules[0].Disabled = true
	in.Results = nil
	tech := technique(t, eval(in), "T0001")
	if tech.Respond.State != domain.LaneGap || tech.Status != domain.StatusGap {
		t.Fatalf("respond %s, status %s", tech.Respond.State, tech.Status)
	}
	if len(tech.Respond.Automations) != 1 || tech.Respond.Automations[0].Lane != domain.LaneGap ||
		!hasGap(tech, domain.LaneRespond, domain.FixEnablePlaybook) {
		t.Errorf("draft row %+v, gaps %+v", tech.Respond.Automations, tech.Gaps)
	}
	// Beside an ACTIVE one, the ACTIVE one decides.
	in.Rules[0].Disabled = false
	in.Automations = append(in.Automations, domain.Automation{ID: "au2", Name: "live", State: "ACTIVE", TriggerRules: []string{"pc.rule.a"}})
	if r := technique(t, eval(in), "T0001").Respond; r.State != domain.LaneEvidenced {
		t.Errorf("with an active automation: %+v", r)
	}
}

// TestHR680_SubtechniqueCapNamesNoFix: a lane capped only by the
// sub-technique rule carries SUBTECHNIQUES_ONLY with its "covers N of M"
// text and no fix; never a gateway route while every route is ENFORCED, and
// never "ships no control" on a lane that is not NONE_SHIPPED. A lane with
// another reason keeps that reason's fix (G0 M28 D720b L1).
// Covers: F960, F962, HR-680
func TestHR680_SubtechniqueCapNamesNoFix(t *testing.T) {
	check := func(t *testing.T, tech domain.Technique, lane domain.Lane) {
		t.Helper()
		var n int
		for _, g := range tech.Gaps {
			if g.Fix.Kind == domain.FixNone || (g.Fix.Kind == domain.FixRouteThroughGateway && lane == domain.LanePrevent) {
				t.Errorf("%s: gap %+v", lane, g)
			}
			if g.Lane != lane {
				continue
			}
			n++
			if g.Reason != domain.ReasonSubtechniquesOnly || g.Fix.Kind != "" || g.Fix.Label != "covers 1 of 2 sub-techniques" {
				t.Errorf("%s: gap %+v", lane, g)
			}
		}
		if n != 1 {
			t.Errorf("%s: %d gaps in %+v", lane, n, tech.Gaps)
		}
	}
	t.Run("prevent, every route enforced", func(t *testing.T) {
		tech := technique(t, eval(business()), "T0002")
		if tech.Prevent.State != domain.LanePartial || len(tech.Prevent.Reasons) != 1 {
			t.Fatalf("prevent %+v", tech.Prevent)
		}
		check(t, tech, domain.LanePrevent)
	})
	t.Run("detect and respond", func(t *testing.T) {
		m := fixtureMapping()
		m.Techniques["T0002.001"] = domain.TechniqueMap{Rules: []string{"pc.rule.a"}}
		tech := technique(t, domain.Evaluate(fixtureCatalog(), m, business()), "T0002")
		if tech.Detect.State != domain.LanePartial || tech.Respond.State != domain.LanePartial {
			t.Fatalf("detect %+v respond %+v", tech.Detect, tech.Respond)
		}
		check(t, tech, domain.LaneDetect)
		check(t, tech, domain.LaneRespond)
	})
	t.Run("another reason keeps its fix", func(t *testing.T) {
		in := business()
		in.Routes[0].State = "PARTIAL"
		tech := technique(t, eval(in), "T0002")
		if !hasReason(tech.Prevent.Reasons, domain.ReasonSubtechniquesOnly) || !hasGap(tech, domain.LanePrevent, domain.FixRouteThroughGateway) {
			t.Errorf("prevent %+v gaps %+v", tech.Prevent, tech.Gaps)
		}
	})
}

// TestHR689_TestLaneCountsOnlyServerObservedUnchangedResults: the Test lane
// counts the newest result of an unchanged library scenario, a PASS only
// when every step was server-observed, within 30 days (G0 M28 D713).
// Covers: F960, HR-689, T-301
func TestHR689_TestLaneCountsOnlyServerObservedUnchangedResults(t *testing.T) {
	r := func(verdict, by, digest string, age time.Duration) domain.Result {
		return domain.Result{ScenarioID: "RT-001", RangeID: "r", Digest: digest, Verdict: verdict, ObservedBy: by, RecordedAt: now.Add(-age)}
	}
	day := 24 * time.Hour
	for _, tc := range []struct {
		name    string
		results []domain.Result
		state   domain.TestState
		reason  domain.Reason
	}{
		{"server pass", []domain.Result{r("PASS", "SERVER", "d1", day)}, domain.TestPassed, ""},
		{"client pass", []domain.Result{r("PASS", "CLIENT", "d1", day)}, domain.TestNotRun, domain.ReasonReportedOnly},
		{"mixed pass", []domain.Result{r("PASS", "MIXED", "d1", day)}, domain.TestNotRun, domain.ReasonReportedOnly},
		{"fail", []domain.Result{r("FAIL", "SERVER", "d1", day)}, domain.TestFailed, domain.ReasonTestFailed},
		{"old pass", []domain.Result{r("PASS", "SERVER", "d1", 31*day)}, domain.TestStale, domain.ReasonTestStale},
		{"changed scenario", []domain.Result{r("PASS", "SERVER", "d0", day)}, domain.TestNotRun, domain.ReasonNeverRun},
		{"error", []domain.Result{r("ERROR", "SERVER", "d1", day)}, domain.TestNotRun, domain.ReasonNeverRun},
		{"newest wins", []domain.Result{r("PASS", "SERVER", "d1", 2*day), r("FAIL", "SERVER", "d1", day)}, domain.TestFailed, domain.ReasonTestFailed},
		{"never run", nil, domain.TestNotRun, domain.ReasonNeverRun},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := business()
			in.Results = tc.results
			tech := technique(t, eval(in), "T0001")
			if tech.Test.State != tc.state || (tc.reason != "" && !hasReason(tech.Test.Reasons, tc.reason)) {
				t.Fatalf("test %s %v, want %s %s", tech.Test.State, tech.Test.Reasons, tc.state, tc.reason)
			}
			if tc.state != domain.TestPassed && !hasGap(tech, domain.LaneTest, domain.FixRunScenario) {
				t.Errorf("no RUN_SCENARIO fix: %+v", tech.Gaps)
			}
		})
	}
	in := business()
	in.Results = []domain.Result{r("PASS", "SERVER", "d0", 24*time.Hour)}
	if s := technique(t, eval(in), "T0001").Test.Scenarios[0]; s.Reason != domain.ReasonScenarioChanged {
		t.Errorf("changed scenario row %+v", s)
	}
	if tl := technique(t, eval(business()), "T0002").Test; tl.State != domain.TestNotRun || tl.Reasons[0] != domain.ReasonNoScenario {
		t.Errorf("no scenario: %+v", tl)
	}
}

func hasGap(t domain.Technique, l domain.Lane, k domain.FixKind) bool {
	for _, g := range t.Gaps {
		if g.Lane == l && g.Fix.Kind == k {
			if k == domain.FixRunScenario && g.Fix.Command != "pclaw redteam run --technique "+t.ID {
				return false
			}
			return true
		}
	}
	return false
}

// TestHR680_StatusRules: green needs Prevent or Detect EVIDENCED and no
// failed test; a test never raises a status; outside and unaddressed
// techniques read as such (D713).
// Covers: F960, HR-680, HR-689
func TestHR680_StatusRules(t *testing.T) {
	mp := eval(business())
	if s := technique(t, mp, "T0001").Status; s != domain.StatusEvidenced {
		t.Errorf("T0001 %s", s)
	}
	in := business()
	in.Results[0].Verdict = "FAIL"
	if s := technique(t, eval(in), "T0001").Status; s != domain.StatusPartial {
		t.Errorf("a failed test leaves %s, want PARTIAL", s)
	}
	in = business()
	in.Agents, in.Rules, in.Automations = nil, nil, nil
	tech := technique(t, eval(in), "T0001")
	if tech.Status != domain.StatusPartial || tech.Test.State != domain.TestPassed {
		// Prevent GAP, Detect PARTIAL (silent rule), Respond GAP, Test PASSED.
		t.Errorf("status %s with lanes %s %s %s %s", tech.Status, tech.Prevent.State, tech.Detect.State, tech.Respond.State, tech.Test.State)
	}
	m := fixtureMapping()
	m.Techniques["T0001"] = domain.TechniqueMap{Scenarios: []string{"RT-001"}}
	if s := technique(t, domain.Evaluate(fixtureCatalog(), m, business()), "T0001").Status; s != domain.StatusGap {
		t.Errorf("a passed test alone raised the status to %s", s)
	}
	out := technique(t, mp, "T0003")
	if out.Status != domain.StatusOutside || out.Outside == nil || len(out.Gaps) != 0 {
		t.Errorf("outside %+v", out)
	}
	if sub := technique(t, mp, "T0003.001"); sub.Status != domain.StatusOutside {
		t.Errorf("an outside technique's sub-technique: %s", sub.Status)
	}
	un := technique(t, mp, "T0004")
	if un.Status != domain.StatusGap || un.UnaddressedWhy == "" || len(un.Gaps) != 1 || un.Gaps[0].Fix.Kind != domain.FixNone {
		t.Errorf("unaddressed %+v", un)
	}
	if _, ok := mp.Technique("T0005"); ok {
		t.Error("a deprecated technique is a cell")
	}
}

// TestHR680_SubtechniquesOnlyCapAtPartial: a lane fed only by sub-technique
// mappings is at most PARTIAL and says how many it covers; each
// sub-technique is evaluated with its own lanes (D712).
// Covers: F960, F961, HR-680
func TestHR680_SubtechniquesOnlyCapAtPartial(t *testing.T) {
	mp := eval(business())
	tech := technique(t, mp, "T0002")
	if tech.Prevent.State != domain.LanePartial || !hasReason(tech.Prevent.Reasons, domain.ReasonSubtechniquesOnly) {
		t.Fatalf("prevent %+v", tech.Prevent)
	}
	if tech.Prevent.Detail != "covers 1 of 2 sub-techniques" {
		t.Errorf("detail %q", tech.Prevent.Detail)
	}
	if tech.Status != domain.StatusPartial || len(tech.Subtechniques) != 2 {
		t.Errorf("status %s, %d sub-techniques", tech.Status, len(tech.Subtechniques))
	}
	if s := technique(t, mp, "T0002.001"); s.Prevent.State != domain.LaneEvidenced || s.Status != domain.StatusEvidenced || s.Parent != "T0002" {
		t.Errorf("T0002.001 %+v", s.Prevent)
	}
	if s := technique(t, mp, "T0002.002"); s.Prevent.State != domain.LaneNoneShipped {
		t.Errorf("T0002.002 %+v", s.Prevent)
	}
	if c := technique(t, mp, "T0002").Seen.AlertsRaised; c != 2 {
		t.Errorf("seen alerts of the technique and its sub-techniques: %d", c)
	}
}

// TestHR680_SeenAndTacticCounts: Seen counts alerts carrying the technique
// and refusals and holds by mapped controls; a technique under two tactics
// counts in both (D713).
// Covers: F960, HR-680
func TestHR680_SeenAndTacticCounts(t *testing.T) {
	mp := eval(business())
	s := technique(t, mp, "T0001").Seen
	if s.AlertsRaised != 3 || s.Refusals != 5 || s.Holds != 1 || s.WindowDays != 30 {
		t.Errorf("seen %+v", s)
	}
	want := map[string][4]int{"execution": {1, 1, 0, 0}, "exfiltration": {1, 0, 1, 1}}
	for _, tc := range mp.Tactics {
		got := [4]int{tc.Evidenced, tc.Partial, tc.Gap, tc.Outside}
		if got != want[tc.ShortName] {
			t.Errorf("%s: %v, want %v (%v)", tc.ShortName, got, want[tc.ShortName], tc.TechniqueIDs)
		}
	}
	if mp.Statement != domain.Statement || mp.MappingDigest != "m0" || mp.CatalogVersion != "20.0" {
		t.Errorf("header %+v", mp)
	}
}

// TestHR687_DropsAndCodes: a snapshot code round-trips, and Prevent, Detect
// or Respond leaving EVIDENCED, or Test going PASSED to FAILED, is a drop
// (D719).
// Covers: F972, F973, HR-687, T-300
func TestHR687_DropsAndCodes(t *testing.T) {
	before := eval(business()).Codes()
	if before["T0001"] != "E E E P E" {
		t.Fatalf("T0001 code %q", before["T0001"])
	}
	in := business()
	in.Rules[0].Disabled = true
	in.Results[0].Verdict = "FAIL"
	after := eval(in).Codes()
	drops := domain.Drops(before, after)
	want := []domain.Drop{
		{TechniqueID: "T0001", Lane: domain.LaneDetect, From: "EVIDENCED", To: "GAP"},
		{TechniqueID: "T0001", Lane: domain.LaneRespond, From: "EVIDENCED", To: "PARTIAL"},
		{TechniqueID: "T0001", Lane: domain.LaneTest, From: "PASSED", To: "FAILED"},
	}
	if len(drops) != len(want) {
		t.Fatalf("drops %+v", drops)
	}
	for i := range want {
		if drops[i] != want[i] {
			t.Errorf("drop %d: %+v, want %+v", i, drops[i], want[i])
		}
	}
	delete(after, "T0001")
	if d := domain.Drops(before, after); len(d) != 0 {
		t.Errorf("a technique absent from the new snapshot dropped: %+v", d)
	}
	if c := domain.StatusCounts(before); c[domain.StatusEvidenced] != 1 || c[domain.StatusOutside] != 1 {
		t.Errorf("counts %v", c)
	}
}

// TestHR680_EvaluateIsDeterministic: the same arguments give the same map.
// Covers: F968, HR-688
func TestHR680_EvaluateIsDeterministic(t *testing.T) {
	a, b := eval(business()), eval(business())
	ac, bc := a.Codes(), b.Codes()
	for id, c := range ac {
		if bc[id] != c {
			t.Errorf("%s: %s then %s", id, c, bc[id])
		}
	}
	if len(a.Gaps()) != len(b.Gaps()) {
		t.Error("gaps differ")
	}
}

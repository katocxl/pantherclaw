// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	coverage "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapping"
)

// Windows (D713).
const (
	// InputWindow is how recent a rule's input must be to count as live.
	InputWindow = 7 * 24 * time.Hour
	// EngineWindow is how recently the detection cursor must have moved for
	// an audit-only rule to count as listening.
	EngineWindow = 24 * time.Hour
	// TestWindow is how recent a counted range result must be.
	TestWindow = 30 * 24 * time.Hour
	// SeenDays is the window of the Seen counts.
	SeenDays = 30
)

// Evaluate derives the map of cat's framework from the mapping and the
// inputs (D712, D713). It reads nothing else, so the same arguments always
// give the same map.
func Evaluate(cat *catalog.Catalog, m Mapping, in Inputs) Map {
	e := newEval(cat, m, in)
	out := Map{
		Framework: cat.Framework, CatalogVersion: cat.Version, CatalogDigest: cat.Digest, MappingDigest: m.Digest,
		Scope: in.Scope, EvaluatedAt: in.EvaluatedAt, Statement: Statement, OrgWide: OrgWideLanes(),
		Tactics: []TacticCount{}, Techniques: []Technique{},
	}
	byID := map[string]Technique{}
	for _, t := range cat.Matrix() {
		subs := e.subtechniques(t.ID)
		res := e.technique(t, subs, nil)
		for _, s := range subs {
			res.Subtechniques = append(res.Subtechniques, e.technique(s, nil, res.Outside))
		}
		out.Techniques = append(out.Techniques, res)
		byID[t.ID] = res
	}
	for _, tac := range cat.Tactics {
		tc := TacticCount{ID: tac.ID, ShortName: tac.ShortName, Name: tac.Name, Order: tac.Order, TechniqueIDs: []string{}}
		var in []Technique
		for _, t := range out.Techniques {
			if slices.Contains(t.Tactics, tac.ShortName) {
				in = append(in, t)
			}
		}
		slices.SortFunc(in, func(a, b Technique) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID)) })
		for _, t := range in {
			tc.TechniqueIDs = append(tc.TechniqueIDs, t.ID)
			switch t.Status {
			case StatusEvidenced:
				tc.Evidenced++
			case StatusPartial:
				tc.Partial++
			case StatusGap:
				tc.Gap++
			case StatusOutside:
				tc.Outside++
			}
		}
		out.Tactics = append(out.Tactics, tc)
	}
	return out
}

type eval struct {
	cat      *catalog.Catalog
	m        Mapping
	in       Inputs
	controls map[string]mapping.PreventControl
	rules    map[string]Rule
	agents   []Agent // active, in scope
	routes   RouteCounts
	notEnf   []string // names of in-scope agents with a route that is not enforced
	live     bool     // an active agent in scope had a real transaction in the input window
	rows     map[string]RuleRow
}

func newEval(cat *catalog.Catalog, m Mapping, in Inputs) *eval {
	e := &eval{
		cat: cat, m: m, in: in, controls: map[string]mapping.PreventControl{}, rules: map[string]Rule{},
		rows: map[string]RuleRow{},
	}
	for _, c := range m.Controls {
		e.controls[c.ID] = c
	}
	for _, r := range in.Rules {
		e.rules[r.ID] = r
	}
	for _, a := range in.Agents {
		if a.Active && e.inScope(a) {
			e.agents = append(e.agents, a)
			if !a.LastRealTransaction.IsZero() && in.EvaluatedAt.Sub(a.LastRealTransaction) <= InputWindow {
				e.live = true
			}
		}
	}
	e.countRoutes()
	return e
}

func (e *eval) inScope(a Agent) bool {
	switch {
	case e.in.Scope.AgentID != "":
		return a.ID == e.in.Scope.AgentID
	case e.in.Scope.EnvironmentID != "":
		return a.EnvironmentID == e.in.Scope.EnvironmentID
	}
	return true
}

// countRoutes counts the latest record per route of every active agent in
// scope, plus one UNKNOWN route per such agent with no record (D713).
func (e *eval) countRoutes() {
	names := map[string]bool{}
	for _, a := range e.agents {
		n := 0
		for _, r := range e.in.Routes {
			if r.AgentID != a.ID {
				continue
			}
			n++
			switch r.State {
			case "ENFORCED":
				exp := r.ExpiresAt
				if coverage.Lapse(&exp, nil, e.in.EvaluatedAt) != "" {
					e.routes.Stale++
					names[a.Name] = true
					continue
				}
				e.routes.Enforced++
				continue
			case "PARTIAL":
				e.routes.Partial++
			case "OBSERVE_ONLY":
				e.routes.ObserveOnly++
			default:
				e.routes.Unknown++
			}
			names[a.Name] = true
		}
		if n == 0 {
			e.routes.Unknown++
			names[a.Name] = true
		}
	}
	for n := range names {
		e.notEnf = append(e.notEnf, n)
	}
	slices.Sort(e.notEnf)
}

// subtechniques are t's active sub-techniques.
func (e *eval) subtechniques(id string) []catalog.Technique {
	var out []catalog.Technique
	for _, s := range e.cat.Subtechniques(id) {
		if !s.Deprecated && !s.Revoked {
			out = append(out, s)
		}
	}
	return out
}

// lane gathers one lane's items from the technique and its sub-techniques.
type lane struct {
	own, all []string
	subsWith int // sub-techniques with an item in the lane
}

func gather(own TechniqueMap, subs []TechniqueMap, pick func(TechniqueMap) []string) lane {
	l := lane{own: pick(own), all: slices.Clone(pick(own))}
	for _, s := range subs {
		items := pick(s)
		if len(items) > 0 {
			l.subsWith++
		}
		l.all = append(l.all, items...)
	}
	slices.Sort(l.all)
	l.all = slices.Compact(l.all)
	return l
}

// subOnly caps a lane fed only by sub-technique mappings at PARTIAL (D712).
func subOnly(l lane, subs int, state LaneState, reasons []Reason) (LaneState, []Reason, string) {
	if len(l.own) > 0 || len(l.all) == 0 {
		return state, reasons, ""
	}
	if state.rank() > LanePartial.rank() {
		state = LanePartial
	}
	return state, append(reasons, ReasonSubtechniquesOnly), SubtechniquesText(l.subsWith, subs)
}

func (e *eval) technique(t catalog.Technique, subs []catalog.Technique, parentOutside *mapping.OutsideEntry) Technique {
	own := e.m.Techniques[t.ID]
	res := Technique{
		ID: t.ID, Name: t.Name, Parent: t.Parent, URL: t.URL, Tactics: slices.Clone(t.Tactics),
		Gaps: []Gap{}, Campaigns: []string{}, Seen: Seen{WindowDays: SeenDays},
	}
	outside := own.Outside
	if outside == nil {
		outside = parentOutside
	}
	if outside != nil {
		o := *outside
		res.Outside, res.Status = &o, StatusOutside
		res.Prevent = PreventLane{State: LaneNoneShipped, Reasons: []Reason{ReasonOutside}, Controls: []Control{}, Routes: e.routes}
		res.Detect = DetectLane{State: LaneNoneShipped, Reasons: []Reason{ReasonOutside}, Rules: []RuleRow{}}
		res.Respond = RespondLane{State: LaneNoneShipped, Reasons: []Reason{ReasonOutside}, Automations: []AutomationRow{}}
		res.Test = TestLane{State: TestNotRun, Reasons: []Reason{ReasonOutside}, Scenarios: []ScenarioRow{}}
		return res
	}
	subMaps := make([]TechniqueMap, 0, len(subs))
	ids := []string{t.ID}
	for _, s := range subs {
		subMaps = append(subMaps, e.m.Techniques[s.ID])
		ids = append(ids, s.ID)
	}
	if own.Unaddressed != nil && !mapped(own) {
		res.UnaddressedWhy = own.Unaddressed.Why
		res.Prevent = PreventLane{State: LaneNoneShipped, Reasons: []Reason{ReasonUnaddressed}, Controls: []Control{}, Routes: e.routes}
		res.Detect = DetectLane{State: LaneNoneShipped, Reasons: []Reason{ReasonUnaddressed}, Rules: []RuleRow{}}
		res.Respond = RespondLane{State: LaneNoneShipped, Reasons: []Reason{ReasonUnaddressed}, Automations: []AutomationRow{}}
		res.Test = e.test(gather(own, subMaps, func(m TechniqueMap) []string { return m.Scenarios }), ids)
		res.Status = StatusGap
		res.Gaps = append(res.Gaps, Gap{TechniqueID: t.ID, Reason: ReasonUnaddressed, Fix: Fix{Kind: FixNone, Label: labelNone}})
		return res
	}
	res.Campaigns = gather(own, subMaps, func(m TechniqueMap) []string { return m.Campaigns }).all
	if res.Campaigns == nil {
		res.Campaigns = []string{}
	}
	prevent := gather(own, subMaps, func(m TechniqueMap) []string { return m.Prevent })
	res.Prevent = e.prevent(t.ID, prevent, ids)
	res.Prevent.State, res.Prevent.Reasons, res.Prevent.Detail = subOnly(prevent, len(subs), res.Prevent.State, res.Prevent.Reasons)

	detect := gather(own, subMaps, func(m TechniqueMap) []string {
		return slices.Concat(m.Rules, m.HubRules, m.Kinds)
	})
	res.Detect = e.detect(ids, own, subMaps)
	res.Detect.State, res.Detect.Reasons, res.Detect.Detail = subOnly(detect, len(subs), res.Detect.State, res.Detect.Reasons)

	respond := gather(own, subMaps, func(m TechniqueMap) []string {
		return slices.Concat(m.Rules, m.HubRules, m.HubPlaybooks)
	})
	res.Respond = e.respond(ids, own, subMaps)
	res.Respond.State, res.Respond.Reasons, res.Respond.Detail = subOnly(respond, len(subs), res.Respond.State, res.Respond.Reasons)

	res.Test = e.test(gather(own, subMaps, func(m TechniqueMap) []string { return m.Scenarios }), ids)
	res.Seen = e.seen(ids, prevent.all)
	res.Status = status(res.Prevent.State, res.Detect.State, res.Respond.State, res.Test.State)
	res.Gaps = e.gaps(t.ID, res)
	return res
}

func mapped(m TechniqueMap) bool {
	return len(m.Prevent)+len(m.Rules)+len(m.Kinds)+len(m.Scenarios)+len(m.Campaigns)+len(m.HubRules)+len(m.HubPlaybooks) > 0
}

// status is a technique's color (D713). Test never raises it; a failure
// lowers green to amber.
func status(p, d, r LaneState, t TestState) Status {
	switch {
	case (p == LaneEvidenced || d == LaneEvidenced) && t != TestFailed:
		return StatusEvidenced
	case slices.ContainsFunc([]LaneState{p, d, r}, func(s LaneState) bool { return s == LaneEvidenced || s == LanePartial }):
		return StatusPartial
	}
	return StatusGap
}

func (e *eval) applies(c mapping.PreventControl) bool {
	switch c.Requires {
	case mapping.RequiresAlways:
		return true
	case mapping.RequiresContentSignalsActive:
		return e.in.ContentMode == "ACTIVE" && e.in.Editions.ContentSignals
	case mapping.RequiresMCPCatalogEnforcing:
		return e.in.MCPCatalogEnforcing
	}
	return false
}

// why is the first line found for the technique, then its sub-techniques.
func why(lines map[string]string, ids []string) string {
	for _, id := range ids {
		if w, ok := lines[id]; ok {
			return w
		}
	}
	return ""
}

func (e *eval) prevent(_ string, l lane, ids []string) PreventLane {
	out := PreventLane{Controls: []Control{}, Routes: e.routes}
	if len(l.all) == 0 {
		out.State, out.Reasons = LaneNoneShipped, []Reason{ReasonNoneShipped}
		return out
	}
	anyApplies := false
	for _, id := range l.all {
		c := e.controls[id]
		ok := e.applies(c)
		anyApplies = anyApplies || ok
		out.Controls = append(out.Controls, Control{
			ID: c.ID, Title: c.Title, Surface: string(c.Surface), HR: nonNil(c.HR), ReasonCodes: nonNil(c.ReasonCodes),
			Applies: ok, Why: why(c.Why, ids),
		})
	}
	switch {
	case !anyApplies:
		out.State, out.Reasons = LaneGap, []Reason{ReasonControlOff}
	case e.routes.Total() == 0:
		out.State, out.Reasons = LaneGap, []Reason{ReasonNoRoutes}
	case e.routes.Enforced == 0:
		out.State, out.Reasons = LaneGap, []Reason{ReasonNoEnforcedRoute}
	case e.routes.Enforced < e.routes.Total():
		out.State, out.Reasons = LanePartial, []Reason{ReasonRoutesNotEnforced}
	default:
		out.State, out.Reasons = LaneEvidenced, []Reason{}
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return slices.Clone(s)
}

// audit reports whether every input is an audit.* kind: events that exist
// only when the act happens.
func audit(inputs []string) bool {
	return len(inputs) > 0 && !slices.ContainsFunc(inputs, func(k string) bool { return !strings.HasPrefix(k, "audit.") })
}

// ruleRow evaluates one PantherClaw rule (D713). The result is cached: the
// same rule reads the same in every technique.
func (e *eval) ruleRow(id string, src RuleSource) (RuleRow, bool) {
	key := string(src) + ":" + id
	if r, ok := e.rows[key]; ok {
		return r, true
	}
	row := RuleRow{RuleID: id, Source: src, Inputs: []string{}}
	switch src {
	case SourceBuiltin:
		b := e.m.Builtins[id]
		st := e.rules[id]
		row.Title, row.Inputs = b.Title, nonNil(b.Inputs)
		row.Licensed = !b.Business || e.in.Editions.AdvancedDetections
		row.Disabled, row.Suppressed, row.LastInputAt = st.Disabled, st.Suppressed, st.LastInputAt
	case SourceHub:
		st, ok := e.rules[id]
		if !ok || st.Source != SourceHub {
			return RuleRow{}, false
		}
		row.Title, row.Inputs = st.Title, nonNil(st.Inputs)
		row.Licensed = e.in.Editions.CustomDetections
		row.Disabled, row.Suppressed, row.LastInputAt = st.Disabled || !st.Published, st.Suppressed, st.LastInputAt
	case SourceKind, SourceCustom:
		return RuleRow{}, false
	}
	switch {
	case !row.LastInputAt.IsZero() && e.in.EvaluatedAt.Sub(row.LastInputAt) <= InputWindow:
		row.InputLive = ReasonInputRecent
	case audit(row.Inputs) && e.in.Cursor.CaughtUp && !e.in.Cursor.AdvancedAt.IsZero() &&
		e.in.EvaluatedAt.Sub(e.in.Cursor.AdvancedAt) <= EngineWindow:
		row.InputLive = ReasonEngineLive
	}
	switch {
	case !row.Licensed:
		row.State, row.Reason = LanePartial, ReasonEditionRequired
		row.fix = Fix{Kind: FixUpgradeEdition, TargetID: "business", Label: fmt.Sprintf(labelUpgradeEdition, "Business")}
	case row.Disabled:
		row.State, row.Reason = LaneGap, ReasonRuleOff
		label := fmt.Sprintf(labelEnableRule, id)
		if src == SourceHub {
			label = fmt.Sprintf(labelPublishRule, id)
		}
		row.fix = Fix{Kind: FixEnableRule, TargetID: id, Label: label}
	case row.Suppressed:
		row.State, row.Reason = LanePartial, ReasonRuleSuppressed
		row.fix = Fix{Kind: FixEndSuppression, TargetID: id, Label: fmt.Sprintf(labelEndSuppression, id)}
	case row.InputLive == "":
		row.State, row.Reason = LanePartial, ReasonRuleSilent
		row.fix = Fix{Kind: FixSendEvents, TargetID: id, Label: fmt.Sprintf(labelSendEvents, id, strings.Join(row.Inputs, ", "))}
	default:
		row.State = LaneEvidenced
	}
	e.rows[key] = row
	return row, true
}

// kindRow evaluates one behavior or content signal kind (D713).
func (e *eval) kindRow(k string) RuleRow {
	row := RuleRow{RuleID: k, Title: k, Source: SourceKind, Inputs: []string{}}
	content := strings.HasPrefix(k, "content.")
	if content {
		row.Licensed = e.in.Editions.ContentSignals
	} else {
		row.Licensed = e.in.Editions.BehaviorAnalytics
	}
	if e.live {
		row.InputLive = ReasonInputRecent
	}
	switch {
	case !row.Licensed:
		row.State, row.Reason = LanePartial, ReasonEditionRequired
		row.fix = Fix{Kind: FixUpgradeEdition, TargetID: "business", Label: fmt.Sprintf(labelUpgradeEdition, "Business")}
	case content && e.in.ContentMode != "WATCHING" && e.in.ContentMode != "ACTIVE":
		row.State, row.Reason, row.Disabled = LaneGap, ReasonRuleOff, true
		row.fix = Fix{Kind: FixTurnOnSetting, TargetID: "content_signals", Label: labelTurnOnContent}
	case !e.live:
		row.State, row.Reason = LanePartial, ReasonRuleSilent
		row.fix = Fix{Kind: FixSendEvents, TargetID: k, Label: fmt.Sprintf(labelSendEvents, k, "agent transactions")}
	default:
		row.State = LaneEvidenced
	}
	return row
}

// customTagged reports whether an org custom rule's own tags name one of
// ids.
func customTagged(r Rule, ids []string) bool {
	return slices.ContainsFunc(r.Techniques, func(t string) bool { return slices.Contains(ids, t) })
}

func (e *eval) customLicensed(r Rule) bool {
	return r.Published && !r.Disabled && e.in.Editions.CustomDetections
}

func best[T any](rows []T, state func(T) LaneState) (T, bool) {
	var b T
	found := false
	for _, r := range rows {
		if !found || state(r).rank() > state(b).rank() {
			b, found = r, true
		}
	}
	return b, found
}

func (e *eval) detect(ids []string, own TechniqueMap, subs []TechniqueMap) DetectLane {
	out := DetectLane{Rules: []RuleRow{}, Reasons: []Reason{}}
	var pc []RuleRow
	for _, id := range gather(own, subs, func(m TechniqueMap) []string { return m.Rules }).all {
		r, _ := e.ruleRow(id, SourceBuiltin)
		pc = append(pc, r)
	}
	for _, id := range gather(own, subs, func(m TechniqueMap) []string { return m.HubRules }).all {
		if r, ok := e.ruleRow(id, SourceHub); ok {
			pc = append(pc, r)
		}
	}
	for _, k := range gather(own, subs, func(m TechniqueMap) []string { return m.Kinds }).all {
		pc = append(pc, e.kindRow(k))
	}
	out.Rules = append(out.Rules, pc...)
	stated := false
	for _, r := range e.in.Rules {
		if r.Source != SourceCustom || !customTagged(r, ids) {
			continue
		}
		out.Rules = append(out.Rules, RuleRow{
			RuleID: r.ID, Title: r.Title, Source: SourceCustom, Licensed: e.in.Editions.CustomDetections,
			Disabled: r.Disabled || !r.Published, Suppressed: r.Suppressed, LastInputAt: r.LastInputAt, Inputs: nonNil(r.Inputs),
			State: LaneStated, Reason: ReasonStated,
		})
		stated = stated || e.customLicensed(r)
	}
	if b, ok := best(pc, func(r RuleRow) LaneState { return r.State }); ok {
		out.State = b.State
		if b.Reason != "" {
			out.Reasons = []Reason{b.Reason}
		}
		return out
	}
	if stated {
		out.State, out.Reasons = LaneStated, []Reason{ReasonStated}
		return out
	}
	out.State, out.Reasons = LaneNoneShipped, []Reason{ReasonNoneShipped}
	return out
}

func (e *eval) respond(ids []string, own TechniqueMap, subs []TechniqueMap) RespondLane {
	out := RespondLane{Automations: []AutomationRow{}, Reasons: []Reason{}}
	pcRules := map[string]RuleRow{}
	for _, id := range gather(own, subs, func(m TechniqueMap) []string { return m.Rules }).all {
		pcRules[id], _ = e.ruleRow(id, SourceBuiltin)
	}
	for _, id := range gather(own, subs, func(m TechniqueMap) []string { return m.HubRules }).all {
		if r, ok := e.ruleRow(id, SourceHub); ok {
			pcRules[id] = r
		}
	}
	playbooks := gather(own, subs, func(m TechniqueMap) []string { return m.HubPlaybooks }).all
	if !e.in.Editions.Automations {
		if len(pcRules) == 0 && len(playbooks) == 0 {
			out.State, out.Reasons = LaneNoneShipped, []Reason{ReasonNoneShipped}
			return out
		}
		out.State, out.Reasons = LaneGap, []Reason{ReasonEditionRequired}
		out.Automations = append(out.Automations, AutomationRow{
			Name: "automations", TriggerRules: []string{}, Lane: LaneGap, Reason: ReasonEditionRequired,
			fix: Fix{Kind: FixUpgradeEdition, TargetID: "team", Label: fmt.Sprintf(labelUpgradeEdition, "Team")},
		})
		return out
	}
	var counted []AutomationRow
	stated := false
	for _, a := range e.in.Automations {
		var hits []RuleRow
		custom := false
		for _, rid := range a.TriggerRules {
			if r, ok := pcRules[rid]; ok {
				hits = append(hits, r)
			}
			if r, ok := e.rules[rid]; ok && r.Source == SourceCustom && customTagged(r, ids) {
				custom = true
			}
		}
		if len(hits) == 0 {
			if custom && a.State == "ACTIVE" {
				stated = true
				out.Automations = append(out.Automations, automationRow(a, LaneStated, ReasonStated, Fix{}))
			}
			continue
		}
		var row AutomationRow
		switch {
		case a.State != "ACTIVE":
			row = automationRow(a, LanePartial, ReasonPlaybookDisabled,
				Fix{Kind: FixEnablePlaybook, TargetID: a.ID, Label: fmt.Sprintf(labelEnablePlaybook, a.Name)})
		case !slices.ContainsFunc(hits, func(r RuleRow) bool { return r.Reason != ReasonRuleOff && r.Reason != ReasonEditionRequired }):
			fix := hits[0].fix
			row = automationRow(a, LanePartial, ReasonTriggerRuleOff, fix)
		case a.HasContain && !e.in.Editions.AutomationPlaybooks:
			row = automationRow(a, LanePartial, ReasonEditionRequired,
				Fix{Kind: FixUpgradeEdition, TargetID: "business", Label: fmt.Sprintf(labelUpgradeEdition, "Business")})
		default:
			row = automationRow(a, LaneEvidenced, "", Fix{})
		}
		counted = append(counted, row)
	}
	out.Automations = append(out.Automations, counted...)
	if b, ok := best(counted, func(r AutomationRow) LaneState { return r.Lane }); ok {
		out.State = b.Lane
		if b.Reason != "" {
			out.Reasons = []Reason{b.Reason}
		}
		return out
	}
	if len(playbooks) > 0 {
		out.State, out.Reasons = LaneGap, []Reason{ReasonPlaybookNotInstalled}
		for _, p := range playbooks {
			out.Automations = append(out.Automations, AutomationRow{
				Name: p, HubItem: p, TriggerRules: nonNil(e.m.HubPlaybookRules[p]), Lane: LaneGap, Reason: ReasonPlaybookNotInstalled,
				fix: Fix{Kind: FixInstallHubItem, TargetID: p, Label: fmt.Sprintf(labelInstallHubItem, p)},
			})
		}
		return out
	}
	if stated {
		out.State, out.Reasons = LaneStated, []Reason{ReasonStated}
		return out
	}
	out.State, out.Reasons = LaneNoneShipped, []Reason{ReasonNoneShipped}
	return out
}

func automationRow(a Automation, s LaneState, r Reason, f Fix) AutomationRow {
	return AutomationRow{
		ID: a.ID, Name: a.Name, State: a.State, TriggerRules: nonNil(a.TriggerRules), HasContain: a.HasContain,
		HubItem: a.HubItem, Lane: s, Reason: r, fix: f,
	}
}

// test is the Test lane: the newest result of each mapped scenario whose
// digest is the library's, counted only when it is a server-observed PASS
// or a FAIL (D713, HR-689).
func (e *eval) test(l lane, ids []string) TestLane {
	out := TestLane{Scenarios: []ScenarioRow{}, Reasons: []Reason{}}
	if len(l.all) == 0 {
		out.State, out.Reasons = TestNotRun, []Reason{ReasonNoScenario}
		return out
	}
	var failed, passed, stale, reported bool
	for _, sid := range l.all {
		sc := e.m.Scenarios[sid]
		row := ScenarioRow{ScenarioID: sid, Why: why(sc.Why, ids), State: TestNotRun, Reason: ReasonNeverRun}
		var newest *Result
		changed := false
		for i := range e.in.Results {
			r := &e.in.Results[i]
			if r.ScenarioID != sid {
				continue
			}
			if r.Digest != sc.Digest {
				changed = true
				continue
			}
			if newest == nil || r.RecordedAt.After(newest.RecordedAt) {
				newest = r
			}
		}
		if newest == nil {
			if changed {
				row.Reason = ReasonScenarioChanged
			}
			out.Scenarios = append(out.Scenarios, row)
			continue
		}
		row.Title, row.RecordedAt, row.Verdict, row.ObservedBy, row.RangeID =
			newest.Title, newest.RecordedAt, newest.Verdict, newest.ObservedBy, newest.RangeID
		recent := e.in.EvaluatedAt.Sub(newest.RecordedAt) <= TestWindow
		switch {
		case newest.Verdict == "FAIL" && recent:
			row.State, row.Reason, failed = TestFailed, ReasonTestFailed, true
		case newest.Verdict == "PASS" && newest.ObservedBy != "SERVER":
			row.Reason, reported = ReasonReportedOnly, true
		case newest.Verdict == "PASS" && recent:
			row.State, row.Reason, passed = TestPassed, "", true
		case newest.Verdict == "PASS" || newest.Verdict == "FAIL":
			row.State, row.Reason, stale = TestStale, ReasonTestStale, true
		}
		out.Scenarios = append(out.Scenarios, row)
	}
	switch {
	case failed:
		out.State, out.Reasons = TestFailed, []Reason{ReasonTestFailed}
	case passed:
		out.State = TestPassed
	case stale:
		out.State, out.Reasons = TestStale, []Reason{ReasonTestStale}
	case reported:
		out.State, out.Reasons = TestNotRun, []Reason{ReasonReportedOnly}
	default:
		out.State, out.Reasons = TestNotRun, []Reason{ReasonNeverRun}
	}
	return out
}

// seen counts, in scope and window (the inputs hold only those), the alerts
// that carry the technique or a sub-technique, and the refusals and holds
// whose decisive reason is a mapped control's (D713).
func (e *eval) seen(ids, controls []string) Seen {
	s := Seen{WindowDays: SeenDays}
	for _, g := range e.in.Alerts {
		if slices.ContainsFunc(g.Techniques, func(t string) bool { return slices.Contains(ids, t) }) {
			s.AlertsRaised += g.Count
		}
	}
	codes := map[string]bool{}
	for _, id := range controls {
		for _, c := range e.controls[id].ReasonCodes {
			codes[c] = true
		}
	}
	for _, d := range e.in.Decisions {
		if !codes[d.ReasonCode] {
			continue
		}
		switch d.Decision {
		case "DENY":
			s.Refusals += d.Count
		case "REQUIRE_APPROVAL":
			s.Holds += d.Count
		}
	}
	return s
}

// gaps lists one gap per PARTIAL or GAP lane, and one for a Test lane with
// a mapped scenario that is not PASSED (D713).
func (e *eval) gaps(id string, t Technique) []Gap {
	out := []Gap{}
	if s := t.Prevent.State; s == LanePartial || s == LaneGap {
		out = append(out, Gap{Lane: LanePrevent, TechniqueID: id, Reason: t.Prevent.Reasons[0], Fix: e.preventFix(t.Prevent)})
	}
	if s := t.Detect.State; s == LanePartial || s == LaneGap {
		var f Fix
		reason := firstReason(t.Detect.Reasons)
		for _, r := range t.Detect.Rules {
			if r.State == s && r.Source != SourceCustom {
				f, reason = r.fix, r.Reason
				break
			}
		}
		if f.Kind == "" {
			f = Fix{Kind: FixNone, Label: labelNone}
		}
		out = append(out, Gap{Lane: LaneDetect, TechniqueID: id, Reason: reason, Fix: f})
	}
	if s := t.Respond.State; s == LanePartial || s == LaneGap {
		var f Fix
		reason := firstReason(t.Respond.Reasons)
		for _, r := range t.Respond.Automations {
			if r.Lane == s && r.fix.Kind != "" {
				f, reason = r.fix, r.Reason
				break
			}
		}
		if f.Kind == "" {
			f = Fix{Kind: FixNone, Label: labelNone}
		}
		out = append(out, Gap{Lane: LaneRespond, TechniqueID: id, Reason: reason, Fix: f})
	}
	if t.Test.State != TestPassed && len(t.Test.Scenarios) > 0 {
		out = append(out, Gap{Lane: LaneTest, TechniqueID: id, Reason: firstReason(t.Test.Reasons), Fix: Fix{
			Kind: FixRunScenario, TargetID: id, Label: fmt.Sprintf(labelRunScenario, id), Command: fmt.Sprintf(commandRunScenario, id),
		}})
	}
	return out
}

func firstReason(rs []Reason) Reason {
	if len(rs) == 0 {
		return ""
	}
	return rs[0]
}

func (e *eval) preventFix(p PreventLane) Fix {
	if p.Reasons[0] == ReasonControlOff {
		for _, c := range p.Controls {
			switch e.controls[c.ID].Requires {
			case mapping.RequiresContentSignalsActive:
				return Fix{Kind: FixTurnOnSetting, TargetID: "content_signals", Label: labelContentActive}
			case mapping.RequiresMCPCatalogEnforcing:
				return Fix{Kind: FixTurnOnSetting, TargetID: "mcp_catalog", Label: labelMCPEnforce}
			case mapping.RequiresAlways:
			}
		}
	}
	if len(e.notEnf) == 0 {
		return Fix{Kind: FixRouteThroughGateway, Label: labelRouteAny}
	}
	return Fix{Kind: FixRouteThroughGateway, Label: fmt.Sprintf(labelRouteNamed, namesList(e.notEnf))}
}

func sortGaps(gs []Gap) {
	slices.SortStableFunc(gs, func(a, b Gap) int {
		return cmp.Or(cmp.Compare(a.Fix.Kind, b.Fix.Kind), cmp.Compare(a.Fix.TargetID, b.Fix.TargetID),
			cmp.Compare(a.TechniqueID, b.TechniqueID), cmp.Compare(a.Lane, b.Lane))
	})
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgthreatmap reads the threat map's records and keeps its daily
// snapshots in PostgreSQL (G0 M28 D710, D713, D716, D719).
package pgthreatmap

import (
	"context"
	"encoding/json/v2"
	"maps"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapset"
	"github.com/katocxl/pantherclaw/internal/threatmap/ports"
)

// Store implements ports.Store.
type Store struct{}

var _ ports.Store = Store{}

// Hub install result kinds.
const (
	resultCustomRule = "custom_rule"
	resultAutomation = "automation"
)

// Records implements ports.Store.
func (Store) Records(ctx context.Context, tx db.TenantTx, org ids.OrgID, now time.Time) (ports.Records, error) {
	q := dbq.New(tx)
	var out ports.Records
	var err error
	if out.ContentMode, err = q.ThreatMapContentMode(ctx, org); err != nil {
		return out, err
	}
	mcp, err := q.ThreatMapMCPCatalogMode(ctx, org)
	if err != nil {
		return out, err
	}
	out.MCPCatalogEnforcing = mcp == "ENFORCE"
	if out.Agents, err = agents(ctx, q, org, now); err != nil {
		return out, err
	}
	if out.Routes, err = routes(ctx, q, org); err != nil {
		return out, err
	}
	hubRules, hubAutomations, err := hubInstalls(ctx, q, org)
	if err != nil {
		return out, err
	}
	if out.Rules, err = ruleStates(ctx, q, org, now, hubRules); err != nil {
		return out, err
	}
	cur, err := q.ThreatMapCursor(ctx, org)
	if err != nil {
		return out, err
	}
	out.Cursor = domain.Cursor{CaughtUp: cur.UpdatedAt != nil && cur.Seq >= cur.Head}
	if cur.UpdatedAt != nil {
		out.Cursor.AdvancedAt = *cur.UpdatedAt
	}
	if out.Automations, err = automations(ctx, q, org, hubAutomations); err != nil {
		return out, err
	}
	results, err := q.ThreatMapResults(ctx, org)
	if err != nil {
		return out, err
	}
	out.Results = make([]domain.Result, 0, len(results))
	for _, r := range results {
		out.Results = append(out.Results, domain.Result{
			ScenarioID: r.ScenarioID, RangeID: r.RangeID.String(), Digest: r.ScenarioDigest, Verdict: r.Verdict,
			ObservedBy: r.ObservedBy, RecordedAt: r.RecordedAt,
		})
	}
	return out, nil
}

func agents(ctx context.Context, q *dbq.Queries, org ids.OrgID, now time.Time) ([]domain.Agent, error) {
	rows, err := q.ThreatMapAgents(ctx, org)
	if err != nil {
		return nil, err
	}
	activity, err := q.ThreatMapAgentActivity(ctx, org, now.Add(-domain.InputWindow))
	if err != nil {
		return nil, err
	}
	last := make(map[ids.UUID]time.Time, len(activity))
	for _, a := range activity {
		last[a.AgentID] = a.LastReal
	}
	out := make([]domain.Agent, 0, len(rows))
	for _, r := range rows {
		a := domain.Agent{ID: r.ID.String(), Name: r.Name, Active: r.Active, LastRealTransaction: last[r.ID]}
		if r.EnvironmentID != nil {
			a.EnvironmentID = r.EnvironmentID.String()
		}
		out = append(out, a)
	}
	return out, nil
}

func routes(ctx context.Context, q *dbq.Queries, org ids.OrgID) ([]domain.Route, error) {
	rows, err := q.ThreatMapRoutes(ctx, org)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Route, 0, len(rows))
	for _, r := range rows {
		rt := domain.Route{AgentID: r.AgentID.String(), ConnectionID: r.ConnectionID.String(), Operation: r.Operation, State: r.State}
		if r.ExpiresAt != nil {
			rt.ExpiresAt = *r.ExpiresAt
		}
		out = append(out, rt)
	}
	return out, nil
}

// hubInstalls returns the custom rule rows and the automations INSTALLED
// Hub items made, each with its item's name.
func hubInstalls(ctx context.Context, q *dbq.Queries, org ids.OrgID) (rules, automations map[string]string, err error) {
	rows, err := q.ThreatMapHubInstalls(ctx, org)
	if err != nil {
		return nil, nil, err
	}
	rules, automations = map[string]string{}, map[string]string{}
	for _, r := range rows {
		switch r.ResultKind {
		case resultCustomRule:
			rules[r.ResultRef] = r.Name
		case resultAutomation:
			automations[r.ResultRef] = r.Name
		}
	}
	return rules, automations, nil
}

// ruleStates lists every rule with a state row (built-ins) and every custom
// rule. A custom rule is Hub-origin when its current row is the one a Hub
// install made (D716): a later version is the org's own.
func ruleStates(ctx context.Context, q *dbq.Queries, org ids.OrgID, now time.Time, hubRows map[string]string) ([]domain.Rule, error) {
	states, err := q.ThreatMapRuleStates(ctx, org)
	if err != nil {
		return nil, err
	}
	suppressed, err := q.ThreatMapOrgWideSuppressions(ctx, org, now)
	if err != nil {
		return nil, err
	}
	custom, err := q.ThreatMapCustomRules(ctx, org)
	if err != nil {
		return nil, err
	}
	byID := map[string]domain.Rule{}
	for _, c := range custom {
		r := domain.Rule{ID: c.RuleID, Source: domain.SourceCustom, Published: c.State == "PUBLISHED", Inputs: []string{}}
		if _, ok := hubRows[c.ID.String()]; ok {
			r.Source = domain.SourceHub
		}
		if parsed, err := rules.Parse([]byte(c.Content)); err == nil {
			r.Title, r.Inputs = parsed.Title, mapset.Inputs(parsed)
			r.Techniques = slices.Concat(parsed.ATLAS, parsed.ATTACK)
		}
		byID[r.ID] = r
	}
	builtin := func(id string) domain.Rule {
		if r, ok := byID[id]; ok {
			return r
		}
		return domain.Rule{ID: id, Source: domain.SourceBuiltin, Published: true, Inputs: []string{}}
	}
	for _, s := range states {
		r := builtin(s.RuleID)
		if s.DisabledAt != nil {
			r.Disabled, r.DisabledAt = true, *s.DisabledAt
		}
		if s.LastInputAt != nil {
			r.LastInputAt = *s.LastInputAt
		}
		byID[r.ID] = r
	}
	for _, id := range suppressed {
		r := builtin(id)
		r.Suppressed = true
		byID[r.ID] = r
	}
	out := make([]domain.Rule, 0, len(byID))
	for _, id := range slices.Sorted(maps.Keys(byID)) {
		out = append(out, byID[id])
	}
	return out, nil
}

// automations lists the org's automations with the rule ids their alert
// trigger names (D713) and whether a step contains.
func automations(ctx context.Context, q *dbq.Queries, org ids.OrgID, hub map[string]string) ([]domain.Automation, error) {
	rows, err := q.ThreatMapAutomations(ctx, org)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Automation, 0, len(rows))
	for _, r := range rows {
		a := domain.Automation{ID: r.ID.String(), Name: r.Name, State: r.State, HubItem: hub[r.ID.String()]}
		if d, err := autodomain.Parse(r.Definition); err == nil {
			a.TriggerRules, a.Narrowed, a.HasContain = triggers(d)
		}
		out = append(out, a)
	}
	return out, nil
}

// alertEvents are the events a Respond trigger reads rule ids from (D713).
var alertEvents = []string{"alert.raised", "alert.inferred"}

func triggers(d *autodomain.Definition) ([]string, bool, bool) {
	var ids []string
	narrowed := false
	if e := d.When.Event; e != nil && slices.Contains(alertEvents, e.On) {
		ids, narrowed = celenv.TriggerRulesNarrowed(e.Where)
	}
	contain := slices.ContainsFunc(d.Do, func(s autodomain.StepSpec) bool { return s.Step == autodomain.KindContain })
	return ids, narrowed, contain
}

// Seen implements ports.Store.
func (Store) Seen(ctx context.Context, tx db.TenantTx, org ids.OrgID, since time.Time, all bool, agents []ids.UUID) (ports.Seen, error) {
	q := dbq.New(tx)
	if agents == nil {
		agents = []ids.UUID{}
	}
	groups, err := q.ThreatMapAlertGroups(ctx, dbq.ThreatMapAlertGroupsParams{OrgID: org, Since: since, AllAgents: all, Agents: agents})
	if err != nil {
		return ports.Seen{}, err
	}
	decisions, err := q.ThreatMapDecisionCounts(ctx, dbq.ThreatMapDecisionCountsParams{OrgID: org, Since: since, AllAgents: all, Agents: agents})
	if err != nil {
		return ports.Seen{}, err
	}
	out := ports.Seen{Alerts: make([]domain.AlertGroup, 0, len(groups)), Decisions: make([]domain.DecisionCount, 0, len(decisions))}
	for _, g := range groups {
		out.Alerts = append(out.Alerts, domain.AlertGroup{Techniques: g.Techniques, Count: g.N})
	}
	for _, d := range decisions {
		out.Decisions = append(out.Decisions, domain.DecisionCount{ReasonCode: d.ReasonCode, Decision: d.Decision, Count: d.N})
	}
	return out, nil
}

// EnvironmentPath implements ports.Store: the org, its team's business
// unit, its team, then the environment, as tenancy scopes a binding.
func (Store) EnvironmentPath(ctx context.Context, tx db.TenantTx, org ids.OrgID, env ids.UUID) (td.Path, bool, error) {
	q := dbq.New(tx)
	e, err := q.GetEnvironment(ctx, org, env)
	if db.IsNoRows(err) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	p := td.OrgPath(org)
	if e.TeamID != nil {
		t, err := q.GetTeam(ctx, org, *e.TeamID)
		if err != nil {
			return nil, false, err
		}
		if t.BusinessUnitID != nil {
			p = p.Child(td.ScopeBusinessUnit, *t.BusinessUnitID)
		}
		p = p.Child(td.ScopeTeam, t.ID)
	}
	return p.Child(td.ScopeEnvironment, e.ID), true, nil
}

func date(t time.Time) pgtype.Date {
	y, m, d := t.UTC().Date()
	return pgtype.Date{Time: time.Date(y, m, d, 0, 0, 0, 0, time.UTC), Valid: true}
}

func snapshot(day pgtype.Date, evaluated time.Time, version, catalogDigest, mappingDigest string, states, counts []byte) (ports.Snapshot, error) {
	s := ports.Snapshot{
		Day: day.Time, EvaluatedAt: evaluated, CatalogVersion: version, CatalogDigest: catalogDigest, MappingDigest: mappingDigest,
	}
	if err := json.Unmarshal(states, &s.States); err != nil {
		return s, err
	}
	if err := json.Unmarshal(counts, &s.Counts); err != nil {
		return s, err
	}
	return s, nil
}

// LatestSnapshot implements ports.Store.
func (Store) LatestSnapshot(ctx context.Context, tx db.TenantTx, org ids.OrgID, scopeKey, framework string) (ports.Snapshot, bool, error) {
	r, err := dbq.New(tx).LatestThreatMapSnapshot(ctx, org, scopeKey, framework)
	if db.IsNoRows(err) {
		return ports.Snapshot{}, false, nil
	} else if err != nil {
		return ports.Snapshot{}, false, err
	}
	s, err := snapshot(r.Day, r.EvaluatedAt, r.CatalogVersion, r.CatalogDigest, r.MappingDigest, r.States, r.Counts)
	return s, err == nil, err
}

// SaveSnapshot implements ports.Store.
func (Store) SaveSnapshot(ctx context.Context, tx db.TenantTx, org ids.OrgID, scopeKey, framework string, s ports.Snapshot) error {
	states, err := json.Marshal(s.States, json.Deterministic(true))
	if err != nil {
		return err
	}
	counts, err := json.Marshal(s.Counts, json.Deterministic(true))
	if err != nil {
		return err
	}
	return dbq.New(tx).UpsertThreatMapSnapshot(ctx, dbq.UpsertThreatMapSnapshotParams{
		OrgID: org, ScopeKey: scopeKey, Framework: framework, Day: date(s.Day), EvaluatedAt: s.EvaluatedAt,
		CatalogVersion: s.CatalogVersion, CatalogDigest: s.CatalogDigest, MappingDigest: s.MappingDigest, States: states, Counts: counts,
	})
}

// Snapshots implements ports.Store.
func (Store) Snapshots(ctx context.Context, tx db.TenantTx, org ids.OrgID, scopeKey, framework string, since time.Time) ([]ports.Snapshot, error) {
	rows, err := dbq.New(tx).ThreatMapSnapshotsSince(ctx, dbq.ThreatMapSnapshotsSinceParams{
		OrgID: org, ScopeKey: scopeKey, Framework: framework, Since: date(since),
	})
	if err != nil {
		return nil, err
	}
	out := make([]ports.Snapshot, 0, len(rows))
	for _, r := range rows {
		s, err := snapshot(r.Day, r.EvaluatedAt, r.CatalogVersion, "", r.MappingDigest, r.States, r.Counts)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// DeleteSnapshotsBefore implements ports.Store.
func (Store) DeleteSnapshotsBefore(ctx context.Context, tx db.TenantTx, org ids.OrgID, before time.Time) (int64, error) {
	return dbq.New(tx).DeleteOldThreatMapSnapshots(ctx, org, date(before))
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app generates and serves evidence-backed policy suggestions (G0
// M16 D90–D92; F185; HR-442..445). Each recomputation that touches an
// unused-authority posture finding enqueues, in its own transaction, a job
// that creates or refreshes the finding's suggestion from the evidence of
// the last 30 days; a resolved finding makes it STALE. People list, read
// and dismiss suggestions, or turn one into a policy draft that only the
// M11.1 publication gate can publish (HR-442).
package app

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/automations/securitysteps"
	"github.com/katocxl/pantherclaw/internal/evidence/retention"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	podomain "github.com/katocxl/pantherclaw/internal/posture/domain"
	"github.com/katocxl/pantherclaw/internal/suggestions/domain"
)

// Outcome says what a generation did.
type Outcome string

// Outcomes.
const (
	Skipped   Outcome = "SKIPPED"   // not an unused-authority finding, or a person acted on its suggestion
	Created   Outcome = "CREATED"   // a new OPEN suggestion
	Refreshed Outcome = "REFRESHED" // the OPEN suggestion's evidence replaced
	MadeStale Outcome = "STALE"     // the finding was resolved
)

// Generate creates or refreshes the suggestion of a posture finding, in
// tx (D91). Only an active unused-authority finding with a grant has one;
// a REMEDIATED finding makes its open and drafted suggestions STALE. A
// suggestion a person drafted or dismissed is left as it is.
//
// The evidence is read with no lock, so a reconciliation never waits for
// it (D98a); only just before writing does the generation share-lock the
// finding and re-check it and the latest suggestion. If either changed in
// between, it runs once more, and then skips.
func Generate(ctx context.Context, tx db.TenantTx, finding ids.UUID) (Outcome, error) {
	return generate(ctx, tx, finding, nil)
}

// generate is Generate, calling between (when set) after the first
// evidence read and before the lock.
func generate(ctx context.Context, tx db.TenantTx, finding ids.UUID, between func()) (Outcome, error) {
	for again := true; ; again = false {
		out, changed, err := generateOnce(ctx, tx, finding, between)
		if err != nil || !changed {
			return out, err
		}
		if !again {
			return Skipped, nil // changed twice while it read: the next job takes it
		}
		between = nil
	}
}

// generateOnce is one generation; changed reports that the finding or its
// latest suggestion moved while the evidence was read, and nothing was
// written.
func generateOnce(ctx context.Context, tx db.TenantTx, finding ids.UUID, between func()) (_ Outcome, changed bool, _ error) {
	q, org := dbq.New(tx), tx.OrgID()
	f, err := q.GetPostureFinding(ctx, org, finding)
	if db.IsNoRows(err) {
		return Skipped, false, nil
	} else if err != nil {
		return "", false, err
	}
	if podomain.Kind(f.Kind) != podomain.UnusedAuthority || f.GrantID == nil {
		return Skipped, false, nil
	}
	if podomain.State(f.State) == podomain.Remediated {
		n, err := Resolve(ctx, tx, finding)
		if err != nil || n == 0 {
			return Skipped, false, err
		}
		return MadeStale, false, nil
	}
	if _, ops := domain.RoutesOf(f.AffectedPaths); len(ops) == 0 {
		return Skipped, false, nil // nothing to restrict by operation
	}
	if !podomain.State(f.State).Active() {
		return Skipped, false, nil // accepted for a while: the suggestion stays as it was
	}
	latest, err := q.PeekPolicySuggestionForFinding(ctx, org, finding)
	if skip, err := skipLatest(latest, err); skip || err != nil {
		return Skipped, false, err
	}
	ev, err := gather(ctx, q, org, f)
	if err != nil {
		return "", false, err
	}
	if between != nil {
		between()
	}

	locked, err := q.SuggestionFinding(ctx, org, finding)
	if db.IsNoRows(err) {
		return "", true, nil
	} else if err != nil {
		return "", false, err
	}
	if !sameFinding(f, locked) {
		return "", true, nil
	}
	now, err := q.LatestPolicySuggestionForFinding(ctx, org, finding)
	if err != nil && !db.IsNoRows(err) {
		return "", false, err
	}
	if now.ID != latest.ID || now.State != latest.State || !sameTime(now.FindingRemediatedAt, latest.FindingRemediatedAt) {
		return "", true, nil
	}

	if !latest.ID.IsZero() && domain.State(latest.State) == domain.Open {
		_, err = q.RefreshPolicySuggestion(ctx, dbq.RefreshPolicySuggestionParams{
			OrgID: org, ID: latest.ID, Owners: ev.owners, WindowFrom: ev.from, WindowTo: ev.to, Observed: ev.observed,
			CoverageLimits: ev.limits, Proposed: ev.proposed, ExpectedEffect: ev.effect,
			Uncertainty: string(ev.assessment.Uncertainty), UncertaintyReasons: ev.assessment.Reasons,
		})
		return Refreshed, false, err
	}
	_, err = q.InsertPolicySuggestion(ctx, dbq.InsertPolicySuggestionParams{
		OrgID: org, ID: ids.NewV7(), Kind: string(domain.UnusedAuthority), PostureFindingID: finding, GrantID: *f.GrantID,
		AgentID: ev.agent, Owners: ev.owners, WindowFrom: ev.from, WindowTo: ev.to, Observed: ev.observed,
		CoverageLimits: ev.limits, Proposed: ev.proposed, ExpectedEffect: ev.effect,
		Uncertainty: string(ev.assessment.Uncertainty), UncertaintyReasons: ev.assessment.Reasons,
	})
	return Created, false, err
}

// skipLatest says whether a finding's latest suggestion keeps a generation
// from writing: a person drafted it, or dismissed it and the finding was
// not remediated since.
func skipLatest(latest dbq.PcPolicySuggestion, err error) (bool, error) {
	switch {
	case db.IsNoRows(err):
		return false, nil
	case err != nil:
		return false, err
	case domain.State(latest.State) == domain.Drafted:
		return true, nil
	case domain.State(latest.State) == domain.Dismissed && latest.FindingRemediatedAt == nil:
		return true, nil // dismissed until the finding is next remediated
	}
	return false, nil
}

// sameFinding says whether a finding is as a generation first read it:
// the same state, snapshot, grant and paths.
func sameFinding(a, b dbq.PcPostureFinding) bool {
	return a.State == b.State && a.StateChangedAt.Equal(b.StateChangedAt) && a.LastSnapshotID == b.LastSnapshotID &&
		sameTime(a.RemediatedAt, b.RemediatedAt) && sameID(a.GrantID, b.GrantID) &&
		a.PathsTruncated == b.PathsTruncated && slices.Equal(a.AffectedPaths, b.AffectedPaths)
}

func sameTime(a, b *time.Time) bool { return (a == nil) == (b == nil) && (a == nil || a.Equal(*b)) }

func sameID(a, b *ids.UUID) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

// Resolve applies a finding's remediation to its suggestions, in tx (D91):
// open and drafted ones become STALE, and dismissed ones record that their
// dismissal ended, so a reopened finding gets a new OPEN suggestion. It
// returns how many were made STALE.
func Resolve(ctx context.Context, tx db.TenantTx, finding ids.UUID) (int64, error) {
	q, org := dbq.New(tx), tx.OrgID()
	n, err := q.StalePolicySuggestions(ctx, org, finding)
	if err != nil {
		return 0, err
	}
	if _, err := q.EndPolicySuggestionDismissals(ctx, org, finding); err != nil {
		return 0, err
	}
	return n, nil
}

// evidence is what a suggestion stores.
type evidence struct {
	agent                              ids.UUID
	owners                             []ids.UUID
	from, to                           time.Time
	observed, limits, proposed, effect []byte
	assessment                         domain.Assessment
}

// gather reads a finding's evidence over the window ending now: the grant
// and its agent's owners, the routes the grant reaches in the latest
// snapshot (and the finding's own), their coverage history, the
// operations the grant was used for, and the recorded actions the
// proposed restriction would match.
func gather(ctx context.Context, q *dbq.Queries, org ids.OrgID, f dbq.PcPostureFinding) (evidence, error) {
	var ev evidence
	g, err := q.GetGrant(ctx, org, *f.GrantID)
	if err != nil {
		return ev, fmt.Errorf("suggestions: grant %s: %w", *f.GrantID, err)
	}
	ev.agent = g.AgentID
	a, err := q.GetAgent(ctx, org, g.AgentID)
	if err != nil {
		return ev, err
	}
	ev.owners = []ids.UUID{}
	for _, o := range []*ids.UUID{a.OwnerUserID, a.BackupOwnerUserID} {
		if o != nil && !slices.Contains(ev.owners, *o) {
			ev.owners = append(ev.owners, *o)
		}
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return ev, err
	}
	ev.to = now.UTC()
	ev.from = ev.to.Add(-domain.Window)

	var gaps domain.Gaps
	routes, unused := domain.RoutesOf(f.AffectedPaths)
	snap, err := q.LatestExposureSnapshot(ctx, org)
	switch {
	case db.IsNoRows(err):
		gaps = append(gaps, domain.ReasonSnapshotMissing)
	case err != nil:
		return ev, err
	default:
		if snap.Truncated || len(snap.Gaps) > 0 {
			gaps = append(gaps, domain.ReasonSnapshotIncomplete)
		}
		rows, err := q.SuggestionGrantRoutes(ctx, org, snap.ID, f.GrantID)
		if err != nil {
			return ev, err
		}
		if len(rows) > domain.MaxRoutes {
			rows, gaps = rows[:domain.MaxRoutes], append(gaps, domain.ReasonRoutesTruncated)
		}
		for _, r := range rows {
			routes = append(routes, domain.Route{Agent: r.AgentID, Connection: r.ConnectionID, Operation: r.Operation})
		}
	}
	routes = domain.SortRoutes(routes)
	if f.PathsTruncated {
		gaps = append(gaps, domain.ReasonRoutesTruncated)
	}

	cov, err := coverage(ctx, q, org, routes, ev.from, ev.to, &gaps)
	if err != nil {
		return ev, err
	}

	facts, _ := retention.BoundsOf(retention.NormalizedFacts)
	receipts, _ := retention.BoundsOf(retention.Receipts)
	keep, err := q.SimulationRetentionDays(ctx, int32(facts.Default), int32(receipts.Default)) //nolint:gosec // G115: days ≤ 3650
	if err != nil {
		return ev, err
	}
	collectedDays := int(keep)
	counted := ev.from
	if collectedDays < domain.WindowDays {
		gaps = append(gaps, domain.ReasonRetentionShort)
		counted = ev.to.Add(-time.Duration(max(collectedDays, 0)) * 24 * time.Hour)
	}

	obs, err := q.SuggestionObserved(ctx, dbq.SuggestionObservedParams{OrgID: org, GrantID: f.GrantID, WindowFrom: counted, WindowTo: ev.to})
	if err != nil {
		return ev, err
	}
	counts, order := map[string]int64{}, make([]string, 0, len(obs))
	for _, o := range obs {
		counts[o.Operation], order = o.Actions, append(order, o.Operation)
	}
	observed, truncated := domain.Observed(counts, order)

	ev.assessment = domain.Assess(cov, gaps)
	if truncated {
		ev.assessment.Reasons = append(ev.assessment.Reasons, domain.ReasonObservedTruncated)
		slices.Sort(ev.assessment.Reasons)
	}

	rules := Proposed(ev.agent, unused)

	var effect *domain.Counts
	if collectedDays > 0 {
		e, err := q.SuggestionEffect(ctx, dbq.SuggestionEffectParams{
			OrgID: org, AgentID: ev.agent, Operations: unused, WindowFrom: counted, WindowTo: ev.to,
		})
		if err != nil {
			return ev, err
		}
		effect = &domain.Counts{Matching: e.Matching, NotDenied: e.NotDenied}
	}

	if ev.observed, err = json.Marshal(observed, json.Deterministic(true)); err != nil {
		return ev, err
	}
	limits := ev.assessment.Limits
	if limits == nil {
		limits = []domain.Limit{}
	}
	if ev.limits, err = json.Marshal(limits); err != nil {
		return ev, err
	}
	if ev.proposed, err = json.Marshal(rules); err != nil {
		return ev, err
	}
	ev.effect, err = json.Marshal(domain.ExpectedEffect(effect, collectedDays, cov))
	return ev, err
}

// Proposed is the restriction a suggestion proposes: the rule
// securitysteps.RestrictionDraft writes for the agent over the unused
// operations (D90).
func Proposed(agent ids.UUID, operations []string) []pdomain.Rule {
	return securitysteps.RestrictionDraft(nil, map[ids.UUID][]string{agent: operations}, domain.WindowDays).Rules
}

// coverage reads the routes' coverage history over the window and folds
// it (D91).
func coverage(ctx context.Context, q *dbq.Queries, org ids.OrgID, routes []domain.Route, from, to time.Time, gaps *domain.Gaps,
) ([]domain.RouteCoverage, error) {
	if len(routes) == 0 {
		return nil, nil
	}
	var agents, conns []ids.UUID
	want := map[domain.Route]bool{}
	for _, r := range routes {
		want[r] = true
		if !slices.Contains(agents, r.Agent) {
			agents = append(agents, r.Agent)
		}
		if !slices.Contains(conns, r.Connection) {
			conns = append(conns, r.Connection)
		}
	}
	rows, err := q.SuggestionCoverageHistory(ctx, dbq.SuggestionCoverageHistoryParams{
		OrgID: org, AgentIds: agents, ConnectionIds: conns, WindowFrom: from, WindowTo: to,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) > maxHistory {
		rows, *gaps = rows[:maxHistory], append(*gaps, domain.ReasonHistoryTruncated)
	}
	samples := make([]domain.Sample, 0, len(rows))
	for _, r := range rows {
		rt := domain.Route{Agent: r.AgentID, Connection: r.ConnectionID, Operation: r.Operation}
		if want[rt] {
			samples = append(samples, domain.Sample{Route: rt, State: r.State, At: r.ComputedAt, ExpiresAt: r.ExpiresAt})
		}
	}
	return domain.WindowCoverage(routes, samples, from, to), nil
}

// maxHistory is the coverage history one generation reads (the query's
// limit less one).
const maxHistory = 20000

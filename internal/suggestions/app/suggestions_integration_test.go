// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/automations/securitysteps"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	"github.com/katocxl/pantherclaw/internal/exposure/recompute"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	poapp "github.com/katocxl/pantherclaw/internal/posture/app"
	podomain "github.com/katocxl/pantherclaw/internal/posture/domain"
	"github.com/katocxl/pantherclaw/internal/suggestions/app"
	"github.com/katocxl/pantherclaw/internal/suggestions/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

type emptyFacts struct{}

func (emptyFacts) Catalog(context.Context, ids.OrgID) (map[string]fdomain.Type, error) {
	return map[string]fdomain.Type{}, nil
}

type noDefinitions struct{}

func (noDefinitions) ActiveDefinitionsInTx(context.Context, db.TenantTx, ids.OrgID) ([]*defs.Definition, error) {
	return nil, nil
}

func service(o *exposuretest.Org, e billing.Edition) *app.Service {
	return &app.Service{Pool: o.P, Ents: edition(e), Drafts: securitysteps.NewPolicyDrafts(emptyFacts{}, noDefinitions{},
		celenv.Limits{MaxExpressionBytes: 2048, MaxCost: 5000, MaxComprehensionNesting: 1, EstimatedCollectionSize: 256})}
}

func as(o *exposuretest.Org, scope td.Scope, roles ...td.RoleName) context.Context {
	var bs []td.Binding
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: scope})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject:    td.Subject{Org: o.Org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: o.User}, Bindings: bs},
		Credential: tenancy.CredAccessToken,
	})
}

func orgScope(o *exposuretest.Org) td.Scope { return td.Scope{Type: td.ScopeOrg, ID: o.Org.UUID()} }

// world is an org whose two agents each hold a grant over payments.* that
// was never used: one unused-authority finding each.
func world(t *testing.T) *exposuretest.Org {
	t.Helper()
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 0, "40 days", "payments.*")
	o.Grant(t, o.Other, 0, "40 days", "payments.*")
	reconcile(t, o)
	return o
}

func reconcile(t *testing.T, o *exposuretest.Org) {
	t.Helper()
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		rec, err := exapp.Recompute(ctx, tx, "manual", 0)
		if err != nil {
			return err
		}
		_, err = poapp.Reconcile(ctx, tx, rec)
		return err
	})
}

// unused returns each agent's unused-authority finding.
func unused(t *testing.T, o *exposuretest.Org) map[ids.UUID]dbq.PcPostureFinding {
	t.Helper()
	out := map[ids.UUID]dbq.PcPostureFinding{}
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListPostureFindings(ctx, dbq.ListPostureFindingsParams{
			OrgID: o.Org, States: []string{}, MaxRows: 200, AllAgents: true, AgentIds: []ids.UUID{}, OrgScope: true,
		})
		for _, r := range rows {
			if podomain.Kind(r.Kind) == podomain.UnusedAuthority && r.AgentID != nil {
				out[*r.AgentID] = r
			}
		}
		return err
	})
	if len(out) != 2 {
		t.Fatalf("unused-authority findings: %d", len(out))
	}
	return out
}

// generate runs each finding's generation and returns each agent's latest
// suggestion.
func generate(t *testing.T, o *exposuretest.Org) (map[ids.UUID]dbq.PcPolicySuggestion, map[ids.UUID]app.Outcome) {
	t.Helper()
	out, outcomes := map[ids.UUID]dbq.PcPolicySuggestion{}, map[ids.UUID]app.Outcome{}
	for agent, f := range unused(t, o) {
		o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
			oc, err := app.Generate(ctx, tx, f.ID)
			if err != nil {
				return err
			}
			outcomes[agent] = oc
			s, err := dbq.New(tx).LatestPolicySuggestionForFinding(ctx, o.Org, f.ID)
			if db.IsNoRows(err) {
				return nil
			}
			out[agent] = s
			return err
		})
	}
	return out, outcomes
}

func count(t *testing.T, o *exposuretest.Org, sql string, args ...any) int {
	t.Helper()
	var n int
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error { return tx.QueryRow(ctx, sql, args...).Scan(&n) })
	return n
}

func refused(t *testing.T, o *exposuretest.Org, sql string, args ...any) {
	t.Helper()
	err := o.P.InTenantTx(context.Background(), o.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
	if err == nil {
		t.Errorf("allowed: %s", sql)
	}
}

// coverage records a coverage snapshot of every route of s's grant in the
// latest exposure snapshot, computed ago (a Postgres interval) ago.
func coverage(t *testing.T, o *exposuretest.Org, s dbq.PcPolicySuggestion, state, ago string) {
	t.Helper()
	o.Exec(t, `WITH r AS (
			SELECT DISTINCT agent_id, connection_id, operation FROM pc.exposure_rights
			WHERE snapshot_id = (SELECT id FROM pc.exposure_snapshots ORDER BY id DESC LIMIT 1) AND grant_id = $2),
		e AS (
			INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body)
			SELECT $1, gen_random_uuid(), 'coverage.test', 'test', 'test', '\x7b7d' FROM r
			RETURNING id),
		n AS (SELECT r.*, row_number() OVER () AS i FROM r),
		m AS (SELECT e.id, row_number() OVER () AS i FROM e)
		INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons, body, body_sha256,
			ledger_entry_id, computed_at)
		SELECT $1, gen_random_uuid(), n.agent_id, n.connection_id, n.operation, $3, '{}', '{}', $4, m.id, now() - $5::interval
		FROM n JOIN m USING (i)`, o.Org, s.GrantID, state, make([]byte, 32), ago)
}

func effect(t *testing.T, s dbq.PcPolicySuggestion) domain.Effect {
	t.Helper()
	var e domain.Effect
	if err := json.Unmarshal(s.ExpectedEffect, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func limits(t *testing.T, s dbq.PcPolicySuggestion) []domain.Limit {
	t.Helper()
	var l []domain.Limit
	if err := json.Unmarshal(s.CoverageLimits, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

// TestHR442_DraftingCreatesADraftAndPublishesNothing (D92): drafting an
// open suggestion stores a policy DRAFT authored by the caller with a
// FORBID of the unused operations for the agent, marks the suggestion
// DRAFTED and audits it, and publishes nothing; the published policy is
// unchanged; a second draft, or a draft without policy.author at the org
// or without posture.read, is refused; and the next generation leaves a
// drafted suggestion alone.
//
// Covers: F185
func TestHR442_DraftingCreatesADraftAndPublishesNothing(t *testing.T) {
	o := world(t)
	got, _ := generate(t, o)
	s := got[o.Agent]
	svc := service(o, billing.Business)
	author := as(o, orgScope(o), td.RoleSecurityAdmin, td.RolePolicyAuthor)

	for name, ctx := range map[string]context.Context{
		"no policy.author": as(o, orgScope(o), td.RoleSecurityAdmin),
		"no posture.read":  as(o, orgScope(o), td.RolePolicyAuthor),
	} {
		if _, _, err := svc.Draft(ctx, s.ID); err == nil {
			t.Errorf("%s: drafted", name)
		}
	}
	if _, _, err := (&app.Service{Pool: o.P, Ents: edition(billing.Business)}).Draft(author, s.ID); !errors.Is(err, app.ErrUnwired) {
		t.Fatalf("no draft store: %v", err)
	}

	drafted, n, err := svc.Draft(author, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if drafted.State != string(domain.Drafted) || drafted.DraftPolicyVersionID == nil || n != 1 {
		t.Fatalf("drafted: %+v %d", drafted, n)
	}
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		v, err := q.GetPolicyVersion(ctx, o.Org, *drafted.DraftPolicyVersionID)
		if err != nil {
			return err
		}
		if v.State != "DRAFT" || v.PublishedAt != nil || !strings.HasPrefix(v.CreatedBy, "user:") {
			t.Fatalf("version: %s %v %s", v.State, v.PublishedAt, v.CreatedBy)
		}
		var b pdomain.Bundle
		if err := json.Unmarshal(v.Bundle, &b); err != nil {
			return err
		}
		i := slices.IndexFunc(b.Rules, func(r pdomain.Rule) bool { return r.ID == securitysteps.RestrictionRuleID(o.Agent) })
		if i < 0 || b.Rules[i].Kind != pdomain.Forbid || len(b.Rules[i].Operations) == 0 {
			t.Fatalf("draft rules: %+v", b.Rules)
		}
		if _, err := q.GetPublishedPolicy(ctx, o.Org); !db.IsNoRows(err) {
			t.Fatalf("published: %v", err)
		}
		return nil
	})
	if c := count(t, o, `SELECT count(*) FROM pc.policy_versions WHERE state <> 'DRAFT'`); c != 0 {
		t.Fatalf("%d versions not drafts", c)
	}
	if c := count(t, o, `SELECT count(*) FROM pc.ledger_entries WHERE kind LIKE '%suggestion.drafted'
		AND convert_from(body, 'UTF8') LIKE '%`+s.ID.String()+`%'`); c != 1 {
		t.Fatalf("drafted audits: %d", c)
	}
	if _, _, err := svc.Draft(author, s.ID); !errors.Is(err, app.ErrState) {
		t.Fatalf("drafted twice: %v", err)
	}
	if c := count(t, o, `SELECT count(*) FROM pc.policy_versions`); c != 1 {
		t.Fatalf("versions: %d", c)
	}
	if _, oc := generate(t, o); oc[o.Agent] != app.Skipped {
		t.Fatalf("regenerated a drafted suggestion: %s", oc[o.Agent])
	}
	// The database keeps a drafted suggestion drafted.
	refused(t, o, `UPDATE pc.policy_suggestions SET state = 'OPEN', draft_policy_version_id = NULL WHERE id = $1`, s.ID)
	refused(t, o, `UPDATE pc.policy_suggestions SET draft_policy_version_id = NULL WHERE id = $1`, s.ID)
}

// TestHR443_EverySuggestionStatesItsWindowLimitsAndUncertainty (D91):
// with no coverage recorded, a suggestion is HIGH with every route an
// UNKNOWN limit; with every route OBSERVE_ONLY since before the window it
// is LOW; a PARTIAL snapshot inside the window refreshes it to MEDIUM. The
// window is 30 days, and the database refuses LOW (or MEDIUM) next to a
// worse limit and a level above LOW with no reason.
//
// Covers: F185
func TestHR443_EverySuggestionStatesItsWindowLimitsAndUncertainty(t *testing.T) {
	o := world(t)
	got, oc := generate(t, o)
	s := got[o.Agent]
	if oc[o.Agent] != app.Created || s.State != string(domain.Open) {
		t.Fatalf("generated: %s %+v", oc[o.Agent], s)
	}
	if d := s.WindowTo.Sub(s.WindowFrom); d != domain.Window {
		t.Fatalf("window %s", d)
	}
	l := limits(t, s)
	if s.Uncertainty != string(domain.High) || len(l) == 0 || !slices.Contains(s.UncertaintyReasons, domain.ReasonCoverageNotAssessed) {
		t.Fatalf("no coverage: %s %v %v", s.Uncertainty, s.UncertaintyReasons, l)
	}
	for _, x := range l {
		if x.State != domain.CoverageUnknown || x.Agent != o.Agent.String() {
			t.Fatalf("limit: %+v", x)
		}
	}
	if len(s.Owners) != 0 {
		t.Fatalf("an unowned agent has owners: %v", s.Owners)
	}

	coverage(t, o, s, domain.CoverageObserveOnly, "40 days")
	got, oc = generate(t, o)
	s = got[o.Agent]
	if oc[o.Agent] != app.Refreshed || s.Uncertainty != string(domain.Low) || len(s.UncertaintyReasons) != 0 {
		t.Fatalf("observe only: %s %s %v", oc[o.Agent], s.Uncertainty, s.UncertaintyReasons)
	}
	if c := count(t, o, `SELECT count(*) FROM pc.policy_suggestions WHERE agent_id = $1`, o.Agent); c != 1 {
		t.Fatalf("refresh inserted: %d", c)
	}

	coverage(t, o, s, domain.CoveragePartial, "2 days")
	got, _ = generate(t, o)
	s = got[o.Agent]
	if s.Uncertainty != string(domain.Medium) || !slices.Contains(s.UncertaintyReasons, domain.ReasonRoutePartial) {
		t.Fatalf("partial: %s %v", s.Uncertainty, s.UncertaintyReasons)
	}
	if e := effect(t, s); !slices.ContainsFunc(e.NotCollected, func(n string) bool { return strings.HasPrefix(n, domain.NotCollectedRoute) }) {
		t.Fatalf("partial routes not listed as not collected: %+v", e)
	}

	other := got[o.Other] // HIGH, with UNKNOWN limits
	for _, sql := range []string{
		`UPDATE pc.policy_suggestions SET uncertainty = 'LOW' WHERE id = $1`,
		`UPDATE pc.policy_suggestions SET uncertainty = 'MEDIUM' WHERE id = $1`,
		`UPDATE pc.policy_suggestions SET uncertainty_reasons = '{}' WHERE id = $1`,
	} {
		refused(t, o, sql, other.ID)
	}
	refused(t, o, `UPDATE pc.policy_suggestions SET uncertainty = 'LOW', uncertainty_reasons = '{}' WHERE id = $1`, s.ID)
}

// TestHR444_SuggestionsVisibleOnlyWithTheGrantAndTheAgent (D92): a
// responder bound at the team of one agent lists, reads and dismisses
// only that agent's suggestion; the other agent's is not found, to read,
// dismiss or draft; a caller without grant.read or posture.read sees
// nothing; below Business the suggestions are refused.
//
// Covers: F185
func TestHR444_SuggestionsVisibleOnlyWithTheGrantAndTheAgent(t *testing.T) {
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 0, "40 days", "payments.*")
	o.Grant(t, o.Other, 0, "40 days", "payments.*")
	team := o.Claim(t, o.Agent)
	reconcile(t, o)
	got, _ := generate(t, o)
	mine, theirs := got[o.Agent], got[o.Other]
	if mine.ID.IsZero() || theirs.ID.IsZero() {
		t.Fatalf("suggestions: %v", got)
	}
	if !slices.Contains(mine.Owners, o.User) {
		t.Fatalf("owners of a claimed agent: %v", mine.Owners)
	}
	svc := service(o, billing.Business)
	org := as(o, orgScope(o), td.RoleSecurityAdmin)
	scoped := as(o, td.Scope{Type: td.ScopeTeam, ID: team}, td.RoleResponder, td.RolePolicyAuthor)

	all, _, err := svc.List(org, nil, "", 50, "")
	if err != nil || len(all) != 2 {
		t.Fatalf("org list: %d %v", len(all), err)
	}
	part, _, err := svc.List(scoped, nil, "", 50, "")
	if err != nil || len(part) != 1 || part[0].ID != mine.ID {
		t.Fatalf("scoped list: %v %v", part, err)
	}
	if _, err := svc.Get(scoped, theirs.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("read a hidden suggestion: %v", err)
	}
	if _, err := svc.Dismiss(scoped, theirs.ID, "not needed by that agent"); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("dismissed a hidden suggestion: %v", err)
	}
	if _, _, err := svc.Draft(scoped, theirs.ID); err == nil {
		t.Fatal("drafted from a hidden suggestion")
	}
	if _, err := svc.Get(scoped, mine.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(scoped, ids.NewV7()); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}

	for name, ctx := range map[string]context.Context{
		"viewer":               as(o, orgScope(o), td.RoleViewer),
		"grant.read only":      as(o, orgScope(o), td.RoleRunLauncher),
		"other team responder": as(o, td.Scope{Type: td.ScopeTeam, ID: ids.NewV7()}, td.RoleResponder),
	} {
		rows, _, err := svc.List(ctx, nil, "", 50, "")
		if err == nil && len(rows) != 0 {
			t.Errorf("%s listed %d", name, len(rows))
		}
		if _, err := svc.Get(ctx, mine.ID); err == nil {
			t.Errorf("%s read a suggestion", name)
		}
	}
	if _, _, err := service(o, billing.Team).List(org, nil, "", 50, ""); !errors.Is(err, app.ErrEdition) {
		t.Fatalf("team edition: %v", err)
	}
	if _, err := service(o, billing.Team).Get(org, mine.ID); !errors.Is(err, app.ErrEdition) {
		t.Fatalf("team edition read: %v", err)
	}

	d, err := svc.Dismiss(scoped, mine.ID, "the owner still needs the refunds")
	if err != nil || d.State != string(domain.Dismissed) || d.DismissReason == nil {
		t.Fatalf("dismiss: %+v %v", d, err)
	}
}

// TestHR445_ExpectedEffectOnlyFromRecordedTransactions (D90): with the
// org's retention covering the window the counts are present, read from
// recorded transactions (zero, never used); routes whose coverage was not
// ENFORCED are listed as not collected; with a retention shorter than the
// window the shortfall is listed and makes the suggestion HIGH.
//
// Covers: F185
func TestHR445_ExpectedEffectOnlyFromRecordedTransactions(t *testing.T) {
	o := world(t)
	got, _ := generate(t, o)
	e := effect(t, got[o.Agent])
	if !e.Collected || e.MatchingActions == nil || *e.MatchingActions != 0 || e.NewlyHeld == nil || *e.NewlyHeld != 0 {
		t.Fatalf("effect: %+v", e)
	}
	if len(e.NotCollected) == 0 || !strings.HasPrefix(e.NotCollected[0], domain.NotCollectedRoute) {
		t.Fatalf("unknown routes not listed: %v", e.NotCollected)
	}

	// The database refuses counts claimed without collection, and a
	// not-collected effect that says nothing.
	for _, body := range []string{
		`{"collected": false, "matching_actions": 0, "not_collected": ["NO_ROUTES"]}`,
		`{"collected": false, "not_collected": []}`,
		`{"collected": "yes"}`,
	} {
		refused(t, o, `UPDATE pc.policy_suggestions SET expected_effect = $2::jsonb WHERE id = $1`, got[o.Agent].ID, body)
	}

	// Normalized facts kept 7 days, in effect now (the 7-day notice is
	// skipped).
	o.D.AdminExec(t, `ALTER TABLE pc.retention_policies DISABLE TRIGGER retention_policies_guard`)
	o.D.AdminExec(t, `INSERT INTO pc.retention_policies (org_id, id, category, revision, days, effective_from)
		SELECT $1, gen_random_uuid(), 'normalized_facts', coalesce(max(revision), 0) + 1, 7, now() FROM pc.retention_policies
		WHERE org_id = $1 AND category = 'normalized_facts'`, o.Org)
	o.D.AdminExec(t, `ALTER TABLE pc.retention_policies ENABLE TRIGGER retention_policies_guard`)
	got, _ = generate(t, o)
	s := got[o.Agent]
	e = effect(t, s)
	if !slices.Contains(e.NotCollected, domain.NotCollectedRetention) || s.Uncertainty != string(domain.High) ||
		!slices.Contains(s.UncertaintyReasons, domain.ReasonRetentionShort) {
		t.Fatalf("short retention: %+v %s %v", e, s.Uncertainty, s.UncertaintyReasons)
	}
}

// TestT196_SuggestionsNeverLoosenPolicy (T-196): a suggestion is inserted
// only OPEN, its identity never changes, it is dismissed only with a
// reason and then left alone by generation while its finding stays open
// (until the finding is next remediated: TestT196_ADismissalLasts…); a
// resolved finding makes its open or drafted suggestion STALE, and a STALE
// one never reopens; a suggestion never writes a policy version by itself.
//
// Covers: F185
func TestT196_SuggestionsNeverLoosenPolicy(t *testing.T) {
	o := world(t)
	got, _ := generate(t, o)
	s := got[o.Agent]
	if c := count(t, o, `SELECT count(*) FROM pc.policy_versions`); c != 0 {
		t.Fatalf("generation wrote %d policy versions", c)
	}
	var proposed []pdomain.Rule
	if err := json.Unmarshal(s.Proposed, &proposed); err != nil {
		t.Fatal(err)
	}
	for _, r := range proposed {
		if r.Kind != pdomain.Forbid {
			t.Fatalf("a suggestion proposed a %s rule", r.Kind)
		}
	}

	for _, sql := range []string{
		`UPDATE pc.policy_suggestions SET agent_id = $2 WHERE id = $1`,
		`UPDATE pc.policy_suggestions SET grant_id = (SELECT grant_id FROM pc.policy_suggestions WHERE agent_id = $2) WHERE id = $1`,
		`UPDATE pc.policy_suggestions SET state = 'DISMISSED' WHERE id = $1 AND $2::uuid IS NOT NULL`,
		`UPDATE pc.policy_suggestions SET state = 'DRAFTED' WHERE id = $1 AND $2::uuid IS NOT NULL`,
		`DELETE FROM pc.policy_suggestions WHERE id = $1 AND $2::uuid IS NOT NULL`,
	} {
		refused(t, o, sql, s.ID, o.Other)
	}
	refused(t, o, `INSERT INTO pc.policy_suggestions (org_id, id, kind, posture_finding_id, grant_id, agent_id, owners, window_from,
		window_to, observed, coverage_limits, proposed, expected_effect, uncertainty, uncertainty_reasons, state, dismissed_by, dismiss_reason)
		SELECT org_id, $2, kind, posture_finding_id, grant_id, agent_id, owners, window_from, window_to, observed, coverage_limits,
		       proposed, expected_effect, uncertainty, uncertainty_reasons, 'DISMISSED', 'x', 'dismissed on insert'
		FROM pc.policy_suggestions WHERE id = $1`, s.ID, ids.NewV7())

	svc := service(o, billing.Business)
	org := as(o, orgScope(o), td.RoleSecurityAdmin)
	if _, err := svc.Dismiss(org, s.ID, "too short"); !errors.Is(err, app.ErrReason) {
		t.Fatalf("short reason: %v", err)
	}
	if _, err := svc.Dismiss(org, s.ID, "the agent runs refunds at month end"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Dismiss(org, s.ID, "the agent runs refunds at month end"); !errors.Is(err, app.ErrState) {
		t.Fatalf("dismissed twice: %v", err)
	}
	if c := count(t, o, `SELECT count(*) FROM pc.ledger_entries WHERE kind LIKE '%suggestion.dismissed'
		AND convert_from(body, 'UTF8') LIKE '%month end%'`); c != 1 {
		t.Fatalf("dismissal audits: %d", c)
	}
	if _, oc := generate(t, o); oc[o.Agent] != app.Skipped {
		t.Fatalf("regenerated a dismissed suggestion: %s", oc[o.Agent])
	}
	refused(t, o, `UPDATE pc.policy_suggestions SET state = 'OPEN' WHERE id = $1`, s.ID)

	// The other agent's grant is revoked: its finding is remediated and its
	// suggestion goes STALE.
	other := got[o.Other]
	o.Revoke(t, other.GrantID)
	reconcile(t, o)
	f := unusedAny(t, o, other.PostureFindingID)
	if f.State != string(podomain.Remediated) {
		t.Fatalf("finding %s", f.State)
	}
	var oc app.Outcome
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		oc, err = app.Generate(ctx, tx, f.ID)
		return err
	})
	if oc != app.MadeStale || count(t, o, `SELECT count(*) FROM pc.policy_suggestions WHERE id = $1 AND state = 'STALE'`, other.ID) != 1 {
		t.Fatalf("stale: %s", oc)
	}
	refused(t, o, `UPDATE pc.policy_suggestions SET state = 'OPEN' WHERE id = $1`, other.ID)
}

// TestT196_ADismissalLastsUntilTheFindingIsNextRemediated (T-196, D91): a
// dismissed suggestion is left alone while its finding stays open; the
// finding's remediation is recorded on it once, by the reconciliation that
// remediates it; when the finding reopens, the next generation starts a
// new OPEN suggestion and the dismissed one stays as it was.
//
// Covers: F185
func TestT196_ADismissalLastsUntilTheFindingIsNextRemediated(t *testing.T) {
	ctx := context.Background()
	o := world(t)
	got, _ := generate(t, o)
	s := got[o.Agent]
	if _, err := service(o, billing.Business).Dismiss(as(o, orgScope(o), td.RoleSecurityAdmin), s.ID,
		"the agent runs refunds at month end"); err != nil {
		t.Fatal(err)
	}
	if _, oc := generate(t, o); oc[o.Agent] != app.Skipped {
		t.Fatalf("regenerated a dismissed suggestion: %s", oc[o.Agent])
	}
	// Only a dismissed suggestion records a remediation.
	refused(t, o, `UPDATE pc.policy_suggestions SET finding_remediated_at = now() WHERE id = $1`, got[o.Other].ID)

	o.Revoke(t, s.GrantID)
	if err := recomputeWith(ctx, o, &app.Queue{Jobs: insertClient(t, o)}, func() {}); err != nil {
		t.Fatal(err)
	}
	f := unusedAny(t, o, s.PostureFindingID)
	if f.State != string(podomain.Remediated) {
		t.Fatalf("finding %s", f.State)
	}
	if c := count(t, o, `SELECT count(*) FROM pc.policy_suggestions WHERE id = $1 AND state = 'DISMISSED'
		AND finding_remediated_at IS NOT NULL`, s.ID); c != 1 {
		t.Fatal("the remediation was not recorded on the dismissed suggestion")
	}
	refused(t, o, `UPDATE pc.policy_suggestions SET finding_remediated_at = now() + interval '1 day' WHERE id = $1`, s.ID)

	o.Exec(t, `UPDATE pc.posture_findings SET state = 'OPEN' WHERE id = $1`, f.ID) // reopened
	var oc app.Outcome
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		oc, err = app.Generate(ctx, tx, f.ID)
		return err
	})
	if oc != app.Created {
		t.Fatalf("reopened: %s", oc)
	}
	if c := count(t, o, `SELECT count(*) FROM pc.policy_suggestions WHERE posture_finding_id = $1 AND state = 'OPEN'`, f.ID); c != 1 {
		t.Fatalf("open suggestions after reopening: %d", c)
	}
	if c := count(t, o, `SELECT count(*) FROM pc.policy_suggestions WHERE id = $1 AND state = 'DISMISSED'`, s.ID); c != 1 {
		t.Fatal("the dismissed suggestion changed")
	}
}

// TestD91_ARemediationDuringAGenerationLeavesTheSuggestionStale (D91): a
// generation and a reconciliation that remediates its finding run at the
// same time, in either order; the later one waits for the earlier one, and
// the suggestion ends STALE with no OPEN one left, the remediation made
// STALE in the reconciliation's own transaction.
//
// Covers: F185
func TestD91_ARemediationDuringAGenerationLeavesTheSuggestionStale(t *testing.T) {
	for _, generationFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "generation first", false: "reconciliation first"}[generationFirst], func(t *testing.T) {
			ctx := context.Background()
			o := world(t)
			got, _ := generate(t, o)
			s := got[o.Agent]
			o.Revoke(t, s.GrantID)
			hook := &app.Queue{Jobs: insertClient(t, o)}

			held, release := make(chan struct{}), make(chan struct{})
			stop := sync.OnceFunc(func() { close(release) })
			defer stop()
			pause := func() { close(held); <-release }
			first, second := make(chan error, 1), make(chan error, 1)
			var outcome app.Outcome
			generation := func(pause func()) error {
				var err error
				outcome, err = generateWith(ctx, o, s.PostureFindingID, pause)
				return err
			}
			if generationFirst {
				go func() { first <- generation(pause) }()
			} else {
				go func() { first <- recomputeWith(ctx, o, hook, pause) }()
			}
			select {
			case <-held:
			case err := <-first:
				t.Fatalf("first transaction: %v", err)
			}
			if generationFirst {
				go func() { second <- recomputeWith(ctx, o, hook, func() {}) }()
			} else {
				go func() { second <- generation(func() {}) }()
			}
			select {
			case err := <-second:
				t.Fatalf("did not wait for the held transaction: %v", err)
			case <-time.After(300 * time.Millisecond):
			}
			stop()
			if err := <-first; err != nil {
				t.Fatal(err)
			}
			if err := <-second; err != nil {
				t.Fatal(err)
			}

			want := app.Skipped // the finding was already remediated and its suggestion STALE
			if generationFirst {
				want = app.Refreshed
			}
			if outcome != want {
				t.Fatalf("generation: %s, want %s", outcome, want)
			}
			if f := unusedAny(t, o, s.PostureFindingID); f.State != string(podomain.Remediated) {
				t.Fatalf("finding %s", f.State)
			}
			if c := count(t, o, `SELECT count(*) FROM pc.policy_suggestions WHERE id = $1 AND state = 'STALE'`, s.ID); c != 1 {
				t.Fatal("the suggestion is not STALE")
			}
			if c := count(t, o, `SELECT count(*) FROM pc.policy_suggestions WHERE posture_finding_id = $1 AND state = 'OPEN'`,
				s.PostureFindingID); c != 0 {
				t.Fatalf("%d open suggestions for a remediated finding", c)
			}
			if n := jobsFor(t, o, s.PostureFindingID); n != 1 {
				t.Fatalf("generation jobs: %d", n)
			}
		})
	}
}

// TestD91_TheGenerationJobCommitsAndRollsBackWithTheReconciliation (D91):
// the recomputation service, with the suggestions' queue as its finding
// hook, enqueues one suggestions.generate job per unused-authority finding
// in the reconciliation's transaction; when that transaction rolls back,
// no job is left.
//
// Covers: F185
func TestD91_TheGenerationJobCommitsAndRollsBackWithTheReconciliation(t *testing.T) {
	ctx := context.Background()
	o := world(t)
	svc := &recompute.Service{Pool: o.P, Ents: edition(billing.Business), Findings: &app.Queue{Jobs: insertClient(t, o)}}
	res, err := svc.Run(ctx, o.Org)
	if err != nil || !res.Recomputed || res.Posture == nil {
		t.Fatalf("run: %+v %v", res, err)
	}
	for agent, f := range unused(t, o) {
		if n := jobsFor(t, o, f.ID); n != 1 {
			t.Fatalf("agent %s: %d generation jobs", agent, n)
		}
	}

	rolled := world(t)
	svc = &recompute.Service{
		Pool: rolled.P, Ents: edition(billing.Business), Findings: failAfter{&app.Queue{Jobs: insertClient(t, rolled)}},
	}
	if _, err := svc.Run(ctx, rolled.Org); !errors.Is(err, errHook) {
		t.Fatalf("run: %v", err)
	}
	for agent, f := range unused(t, rolled) {
		if n := jobsFor(t, rolled, f.ID); n != 0 {
			t.Fatalf("agent %s: %d generation jobs after a rollback", agent, n)
		}
	}
}

var errHook = errors.New("hook failed after enqueueing")

// failAfter enqueues, then fails the reconciliation.
type failAfter struct{ q *app.Queue }

func (f failAfter) FindingChanged(ctx context.Context, tx db.TenantTx, finding ids.UUID, kind podomain.Kind,
	act podomain.ActionKind,
) error {
	if err := f.q.FindingChanged(ctx, tx, finding, kind, act); err != nil {
		return err
	}
	return errHook
}

func insertClient(t *testing.T, o *exposuretest.Org) *jobs.Client {
	t.Helper()
	c, err := jobs.NewClient(o.P, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// recomputeWith recomputes and reconciles with hook in one transaction,
// calling pause before it commits.
func recomputeWith(ctx context.Context, o *exposuretest.Org, hook poapp.FindingHook, pause func()) error {
	return o.P.InTenantTx(ctx, o.Org, func(ctx context.Context, tx db.TenantTx) error {
		rec, err := exapp.Recompute(ctx, tx, "manual", 0)
		if err != nil {
			return err
		}
		if _, err := poapp.ReconcileWith(ctx, tx, rec, hook); err != nil {
			return err
		}
		pause()
		return nil
	})
}

// generateWith runs a finding's generation, calling pause before it
// commits.
func generateWith(ctx context.Context, o *exposuretest.Org, finding ids.UUID, pause func()) (app.Outcome, error) {
	var out app.Outcome
	err := o.P.InTenantTx(ctx, o.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		if out, err = app.Generate(ctx, tx, finding); err != nil {
			return err
		}
		pause()
		return nil
	})
	return out, err
}

// jobsFor counts the committed generation jobs of a finding.
func jobsFor(t *testing.T, o *exposuretest.Org, finding ids.UUID) int {
	t.Helper()
	var n int
	o.D.AdminQueryRow(t, `SELECT count(*) FROM pc.river_job WHERE kind = 'suggestions.generate' AND args->>'finding' = $1`,
		[]any{finding.String()}, &n)
	return n
}

func unusedAny(t *testing.T, o *exposuretest.Org, id ids.UUID) dbq.PcPostureFinding {
	t.Helper()
	var f dbq.PcPostureFinding
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		f, err = dbq.New(tx).GetPostureFinding(ctx, o.Org, id)
		return err
	})
	return f
}

// TestTenancy_policy_suggestions: another org reads none of an org's
// suggestions, cannot read, dismiss or draft one through the service, and
// cannot write one into the org.
//
// Covers: F185
func TestTenancy_policy_suggestions(t *testing.T) {
	o := world(t)
	got, _ := generate(t, o)
	s := got[o.Agent]
	them := exposuretest.NewIn(t, o.D, o.P)
	if n := count(t, them, `SELECT count(*) FROM pc.policy_suggestions`); n != 0 {
		t.Fatalf("another org reads %d suggestions", n)
	}
	svc := service(them, billing.Business)
	ctx := as(them, orgScope(them), td.RoleSecurityAdmin, td.RolePolicyAuthor)
	if _, err := svc.Get(ctx, s.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("read across orgs: %v", err)
	}
	if _, err := svc.Dismiss(ctx, s.ID, "dismissed from another org"); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("dismissed across orgs: %v", err)
	}
	if _, _, err := svc.Draft(ctx, s.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("drafted across orgs: %v", err)
	}
	if rows, _, err := svc.List(ctx, nil, "", 50, ""); err != nil || len(rows) != 0 {
		t.Fatalf("listed across orgs: %d %v", len(rows), err)
	}
	them.Exec(t, `UPDATE pc.policy_suggestions SET state = 'STALE' WHERE id = $1`, s.ID)
	if c := count(t, o, `SELECT count(*) FROM pc.policy_suggestions WHERE id = $1 AND state = 'OPEN'`, s.ID); c != 1 {
		t.Fatal("another org changed the suggestion")
	}
	err := them.P.InTenantTx(context.Background(), them.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.policy_suggestions (org_id, id, kind, posture_finding_id, grant_id, agent_id, owners,
			window_from, window_to, observed, coverage_limits, proposed, expected_effect, uncertainty, uncertainty_reasons)
			VALUES ($1, $2, 'UNUSED_AUTHORITY', $3, $4, $5, '{}', now() - interval '30 days', now(), '{}', '[]',
			$6::jsonb, '{"collected": false, "not_collected": ["NO_ROUTES"]}', 'HIGH', '{NO_ROUTES}')`,
			o.Org, ids.NewV7(), s.PostureFindingID, s.GrantID, s.AgentID, s.Proposed)
		return err
	})
	if err == nil {
		t.Fatal("a suggestion written into another org")
	}
}

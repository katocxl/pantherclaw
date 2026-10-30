// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app computes recommendations on read and records dismissals (G0
// M21 D302, D308; F343). A read runs in a read-only transaction and changes
// nothing (HR-535). It shows only what the viewer may see (HR-536): signals
// from agents cover the agents the viewer's posture.read reaches, and
// recommendations that turn on the org's integrations need posture.read at
// org scope, like a posture finding with no agent (D317).
package app

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/recommendations/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// LedgerKind is the ledger entry kind of a dismissal or its undoing.
const LedgerKind = "recommendation.dismissal"

const (
	// maxReason is the longest dismissal reason, in characters (D313).
	maxReason = 500
	// maxAuditReason is what an audit detail holds, in bytes. The table keeps
	// the whole reason, which in a multi-byte script may be longer than this.
	maxAuditReason = 512
)

// API errors of the service.
var (
	ErrEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"recommendations need the Team edition or above")
	ErrNotFound = pcerr.New(pcerr.NotFound, "RECOMMENDATION_NOT_FOUND", "recommendation not found")
	ErrReason   = pcerr.New(pcerr.InvalidArgument, "RECOMMENDATION_REASON_INVALID",
		"a dismissal needs a reason of 10-500 characters")
	ErrDismissed = pcerr.New(pcerr.FailedPrecondition, "RECOMMENDATION_ALREADY_DISMISSED",
		"the recommendation is already dismissed")
	ErrNotDismissed = pcerr.New(pcerr.FailedPrecondition, "RECOMMENDATION_NOT_DISMISSED",
		"the recommendation is not dismissed")
)

// Service serves recommendations.
type Service struct {
	Pool *db.Pool
	Ents exapp.Entitlements
}

// Dismissal is who dismissed a recommendation.
type Dismissal struct {
	By     string
	Reason string
	At     time.Time
}

// Item is one recommendation as the viewer sees it. Dismissal is set only
// for a viewer with org scope.
type Item struct {
	Entry     domain.Entry
	Evidence  domain.Evidence
	Dismissed bool
	Dismissal *Dismissal
}

// Listing is one read.
type Listing struct {
	Items []Item
	// Restricted: the viewer lacks org scope, so counts cover only their
	// agents and org-wide recommendations are left out.
	Restricted bool
	AsOf       time.Time
}

// entitled is the Team gate. licence.go is left alone: every paid edition
// has recommendations.
func (s *Service) entitled(ctx context.Context) error {
	if s.Ents == nil {
		return ErrEdition
	}
	e, err := s.Ents.Current(ctx)
	if err != nil {
		return err
	}
	if !e.Edition.Paid() {
		return ErrEdition
	}
	return nil
}

// List computes the recommendations the caller may see, in catalog order.
// Dismissed ones are left out unless includeDismissed.
func (s *Service) List(ctx context.Context, includeDismissed bool) (Listing, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Listing{}, err
	}
	if !c.CanAnywhere(td.PermPostureRead) {
		return Listing{}, td.ErrPermissionDenied(td.PermPostureRead)
	}
	if err := s.entitled(ctx); err != nil {
		return Listing{}, err
	}
	out := Listing{Restricted: !c.Can(td.PermPostureRead, td.OrgPath(c.Org))}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		vis, err := exapp.VisibleAgents(ctx, c, q, td.PermPostureRead)
		if err != nil {
			return err
		}
		facts, err := load(ctx, q, c.Org, vis)
		if err != nil {
			return err
		}
		rows, err := q.ListRecommendationDismissals(ctx, c.Org)
		if err != nil {
			return err
		}
		dismissals := make(map[domain.ID]dbq.PcRecommendationDismissal, len(rows))
		for _, r := range rows {
			dismissals[domain.ID(r.RecommendationID)] = r
		}
		if out.AsOf, err = q.DBNow(ctx); err != nil {
			return err
		}
		out.Items = evaluate(facts, dismissals, out.Restricted, includeDismissed)
		return nil
	}, db.ReadOnly())
	return out, err
}

// evaluate applies the catalog to facts.
func evaluate(facts domain.Facts, dismissals map[domain.ID]dbq.PcRecommendationDismissal, restricted, includeDismissed bool) []Item {
	var out []Item
	for _, e := range domain.Catalog() {
		if restricted && e.Reach == domain.OrgWide {
			continue
		}
		ev, ok := e.Evaluate(facts)
		if !ok {
			continue
		}
		it := Item{Entry: e, Evidence: ev}
		if d, ok := dismissals[e.ID]; ok {
			if !includeDismissed {
				continue
			}
			it.Dismissed = true
			if !restricted {
				it.Dismissal = &Dismissal{By: d.DismissedBy, Reason: d.Reason, At: d.DismissedAt}
			}
		}
		out = append(out, it)
	}
	return out
}

// load reads the signals. Every agent-backed query is filtered to vis
// before it counts.
func load(ctx context.Context, q *dbq.Queries, org ids.OrgID, vis exapp.Visible) (domain.Facts, error) {
	agents := orEmpty(vis.IDs)
	f := domain.Facts{Agents: map[string]domain.Group{}, Secrets: map[string]domain.Group{}}
	contexts, err := q.RecommendationAgentContexts(ctx, org, vis.All, agents)
	if err != nil {
		return f, err
	}
	for _, r := range contexts {
		f.Agents[r.Context] = domain.Group{Count: int(r.Agents), IDs: r.Refs}
	}
	secrets, err := q.RecommendationOpenSecrets(ctx, dbq.RecommendationOpenSecretsParams{
		OrgID: org, Kinds: domain.SecretKinds(), AllAgents: vis.All, AgentIds: agents,
	})
	if err != nil {
		return f, err
	}
	for _, r := range secrets {
		f.Secrets[r.SecretKind] = domain.Group{Count: int(r.Discoveries), IDs: r.Refs}
	}
	data, err := q.RecommendationDataAgents(ctx, org, vis.All, agents)
	if err != nil {
		return f, err
	}
	f.DataAgents = domain.Group{Count: int(data.Agents), IDs: data.Refs}
	in, err := q.RecommendationIntegrations(ctx, org)
	if err != nil {
		return f, err
	}
	f.Integrations = domain.Integrations{
		Issuers: in.Issuers, Packages: in.Packages, Channels: in.Channels, SIEM: in.Siem, FactProviders: in.FactProviders,
	}
	switch r, err := q.OnboardingDecision(ctx, org, decisions, false); {
	case err == nil:
		f.FirstDecision = &r.ID
	case !db.IsNoRows(err):
		return f, err
	}
	switch r, err := q.OnboardingHeld(ctx, org); {
	case err == nil:
		f.FirstHold = &r.ID
	case !db.IsNoRows(err):
		return f, err
	}
	return f, nil
}

// decisions are the decisions that show an org is deciding real actions,
// as the onboarding FIRST_DECISION step counts them.
var decisions = []string{"ALLOW", "ALLOW_WITH_OBLIGATIONS", "REQUIRE_APPROVAL", "REQUIRE_STEP_UP", "DENY", "CANNOT_AUTHORIZE"}

func orEmpty(s []ids.UUID) []ids.UUID {
	if s == nil {
		return []ids.UUID{}
	}
	return s
}

// manager is a caller with posture.manage at org scope: a dismissal hides a
// recommendation from everyone in the org (D308).
func manager(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(td.PermPostureManage, td.OrgPath(c.Org))
}

// Dismiss hides a recommendation for the org until it is undone.
func (s *Service) Dismiss(ctx context.Context, id domain.ID, reason string) error {
	c, err := manager(ctx)
	if err != nil {
		return err
	}
	if err := s.entitled(ctx); err != nil {
		return err
	}
	if _, ok := domain.Lookup(id); !ok {
		return ErrNotFound
	}
	reason = strings.TrimSpace(reason)
	if n := utf8.RuneCountInString(reason); n < 10 || n > maxReason {
		return ErrReason
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		n, err := dbq.New(tx).InsertRecommendationDismissal(ctx, dbq.InsertRecommendationDismissalParams{
			OrgID: c.Org, RecommendationID: string(id), DismissedBy: actorString(c.Actor()), Reason: reason,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrDismissed
		}
		return recordChange(ctx, tx, c.Actor(), id, "dismissed", reason)
	})
}

// Undismiss undoes a dismissal. It works in every edition: removing
// something never needs a plan.
func (s *Service) Undismiss(ctx context.Context, id domain.ID) error {
	c, err := manager(ctx)
	if err != nil {
		return err
	}
	if _, ok := domain.Lookup(id); !ok {
		return ErrNotFound
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		n, err := dbq.New(tx).DeleteRecommendationDismissal(ctx, c.Org, string(id))
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotDismissed
		}
		return recordChange(ctx, tx, c.Actor(), id, "undismissed", "")
	})
}

// recordChange writes the ledger entry and the audit event of a change.
func recordChange(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, id domain.ID, event, reason string) error {
	b, err := evdomain.CanonicalBody(map[string]string{"recommendation": string(id), "event": event})
	if err != nil {
		return err
	}
	if _, err := ledger.Append(ctx, tx, LedgerKind, actor, b); err != nil {
		return err
	}
	details := map[string]string{}
	if reason != "" {
		details["reason"] = excerpt(reason)
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "recommendation." + event, Actor: actor, Outcome: audit.Success,
		Object: &audit.Object{Type: "recommendation", ID: string(id)}, Details: details,
	})
	return err
}

// excerpt cuts s to what an audit detail holds, between characters.
func excerpt(s string) string {
	if len(s) <= maxAuditReason {
		return s
	}
	n := maxAuditReason
	for !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func actorString(a evdomain.Actor) string {
	s := a.Type + ":" + a.ID
	if len(s) > 128 {
		return s[:128]
	}
	return s
}

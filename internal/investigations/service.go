// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package investigations

import (
	"context"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// Edition errors (D5).
var (
	ErrTeam     = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "preceding context needs the Team edition or above")
	ErrBusiness = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "comparing runs needs the Business edition or above")
)

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Service serves the run investigation views to a caller: every row is
// scoped by evidence.read where its agent lives, as in the evidence
// explorer (HR-247).
type Service struct {
	Pool     *db.Pool
	Editions Editions
	// Budgets fills the remaining limit of an inspection's budget lines;
	// nil leaves it empty.
	Budgets BudgetLimits
}

// BudgetLimits reports what is left of each budget account's amount limit
// in its current period, by account id, for the accounts the given grants'
// actions debit (grants BudgetState); accounts without an amount limit are
// left out.
type BudgetLimits interface {
	Remaining(ctx context.Context, grants []ids.UUID) (map[ids.UUID]string, error)
}

// callerScope is the caller's evidence.read scope.
type callerScope struct {
	c     tenancy.Caller
	as    *tapp.AgentScope
	q     *dbq.Queries
	paths map[ids.UUID]td.Path
}

// sectionPermissions are the permissions each inspection section needs
// besides evidence.read on the run (HR-401). automation.read is held at
// the org, as the automations read it; every other one where the run's
// agent lives.
var sectionPermissions = map[Section][]td.Permission{
	SectionTimeline:  {td.PermEvidenceRead},
	SectionLineage:   {td.PermEvidenceRead, td.PermAutomationRead},
	SectionBudget:    {td.PermBudgetRead},
	SectionApprovals: {td.PermApprovalRead},
	SectionCoverage:  {td.PermCoverageRead},
	SectionGaps:      {td.PermEvidenceRead, td.PermCoverageRead},
}

// Readable reports whether the caller holds every permission of sec for
// agent's runs.
func (s callerScope) Readable(ctx context.Context, sec Section, agent ids.UUID) (bool, error) {
	perms, ok := sectionPermissions[sec]
	if !ok {
		return false, nil
	}
	for _, p := range perms {
		path := td.OrgPath(s.c.Org)
		if p != td.PermAutomationRead {
			var err error
			if path, err = s.pathOf(ctx, agent); err != nil {
				return false, err
			}
		}
		if !s.c.Can(p, path) {
			return false, nil
		}
	}
	return true, nil
}

func (s callerScope) pathOf(ctx context.Context, agent ids.UUID) (td.Path, error) {
	if p, ok := s.paths[agent]; ok {
		return p, nil
	}
	a, err := s.q.GetAgent(ctx, s.c.Org, agent)
	if err != nil {
		return td.Path{}, err
	}
	p, err := agents.PathOf(ctx, s.q, a)
	if err != nil {
		return td.Path{}, err
	}
	s.paths[agent] = p
	return p, nil
}

func (s callerScope) Visible(ctx context.Context, agent ids.UUID) (bool, error) {
	return s.as.Can(ctx, agent)
}

func (s callerScope) Limited() bool {
	return !s.c.Can(td.PermEvidenceRead, td.OrgPath(s.c.Org))
}

// entitlements returns the licence's entitlements; without a source, the
// Community edition (fail closed).
func (s *Service) entitlements(ctx context.Context) (billing.Entitlements, error) {
	if s.Editions == nil {
		return billing.CommunityEntitlements(), nil
	}
	return s.Editions.Current(ctx)
}

func (s *Service) read(ctx context.Context, fn func(context.Context, db.TenantTx, Scope) error) error {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return err
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		return fn(ctx, tx, callerScope{c: c, q: q, as: tapp.NewAgentScope(c, q, td.PermEvidenceRead), paths: map[ids.UUID]td.Path{}})
	}, db.ReadOnly())
}

// WhatHappened is F239 for the caller (Community).
func (s *Service) WhatHappened(ctx context.Context, txn ids.UUID) (Happened, error) {
	var out Happened
	err := s.read(ctx, func(ctx context.Context, tx db.TenantTx, sc Scope) error {
		var err error
		out, err = WhatHappened(ctx, tx, sc, txn)
		return err
	})
	return out, err
}

// RunTimeline is F284 for the caller (Community); inferred phases (F232)
// come with the Team edition.
func (s *Service) RunTimeline(ctx context.Context, run ids.UUID) (Timeline, error) {
	e, err := s.entitlements(ctx)
	if err != nil {
		return Timeline{}, err
	}
	var out Timeline
	err = s.read(ctx, func(ctx context.Context, tx db.TenantTx, sc Scope) error {
		var err error
		out, err = RunTimeline(ctx, tx, sc, run, e.ReflexTeam())
		return err
	})
	return out, err
}

// InspectRun is F224, F065, F227 and F229 for the caller (Community);
// inferred phases come with the Team edition. Each section is read only
// with its own permission (HR-401).
func (s *Service) InspectRun(ctx context.Context, run ids.UUID, o InspectOptions) (Inspection, error) {
	e, err := s.entitlements(ctx)
	if err != nil {
		return Inspection{}, err
	}
	o.WithPhases = e.ReflexTeam()
	var out Inspection
	err = s.read(ctx, func(ctx context.Context, tx db.TenantTx, sc Scope) error {
		var err error
		out, err = InspectRun(ctx, tx, sc.(callerScope), run, o)
		return err
	})
	if err != nil {
		return Inspection{}, err
	}
	if s.Budgets != nil && len(out.Budget) > 0 && len(out.Grants) > 0 {
		left, err := s.Budgets.Remaining(ctx, out.Grants)
		if err != nil {
			return Inspection{}, err
		}
		for i, l := range out.Budget {
			if l.IsAccount {
				out.Budget[i].Remaining = left[l.Account]
			}
		}
	}
	return out, nil
}

// PrecedingContext is F241 and F248 for the caller (Team).
func (s *Service) PrecedingContext(ctx context.Context, run ids.UUID, txn *ids.UUID, rng Range) (Preceding, error) {
	e, err := s.entitlements(ctx)
	if err != nil {
		return Preceding{}, err
	}
	if !e.Cases() {
		return Preceding{}, ErrTeam
	}
	var out Preceding
	err = s.read(ctx, func(ctx context.Context, tx db.TenantTx, sc Scope) error {
		var err error
		out, err = PrecedingContext(ctx, tx, sc, run, txn, rng)
		return err
	})
	return out, err
}

// CompareRun is F234 for the caller (Business).
func (s *Service) CompareRun(ctx context.Context, run ids.UUID, ref Range) (Comparison, error) {
	e, err := s.entitlements(ctx)
	if err != nil {
		return Comparison{}, err
	}
	if !e.AdvancedDetections() {
		return Comparison{}, ErrBusiness
	}
	var out Comparison
	err = s.read(ctx, func(ctx context.Context, tx db.TenantTx, sc Scope) error {
		var err error
		out, err = CompareRun(ctx, tx, sc, run, ref)
		return err
	})
	return out, err
}

// MaxScopedAgents bounds a scoped viewer's visible-agent list (D60).
const MaxScopedAgents = 10000

// ErrTooManyAgents refuses a scoped read over more agents than one list holds.
var ErrTooManyAgents = pcerr.New(pcerr.ResourceExhausted, "SCOPE_TOO_LARGE",
	"the caller's scope covers more agents than one read can list; ask for an organization-wide role")

// Agents lists the agents the caller may read (D60).
func (s callerScope) Agents(ctx context.Context) ([]ids.UUID, error) {
	all, err := s.q.InvOrgAgents(ctx, s.c.Org)
	if err != nil {
		return nil, err
	}
	if len(all) > MaxScopedAgents {
		return nil, ErrTooManyAgents
	}
	out := []ids.UUID{}
	for _, a := range all {
		ok, err := s.as.Can(ctx, a)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, a)
		}
	}
	return out, nil
}

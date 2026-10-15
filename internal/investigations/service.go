// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package investigations

import (
	"context"

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
}

// callerScope is the caller's evidence.read scope.
type callerScope struct {
	c  tenancy.Caller
	as *tapp.AgentScope
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
		return fn(ctx, tx, callerScope{c: c, as: tapp.NewAgentScope(c, dbq.New(tx), td.PermEvidenceRead)})
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

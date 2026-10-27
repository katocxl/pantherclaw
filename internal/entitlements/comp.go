// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package entitlements

import (
	"context"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// MaxComp is the longest a comp plan may run (HR-358).
const MaxComp = 365 * 24 * time.Hour

// Comp plan errors.
var (
	ErrInvalidComp = pcerr.New(pcerr.InvalidArgument, "INVALID_COMP",
		"a comp plan needs a plan, an edition, a reason and an end within a year")
	ErrNoComp = pcerr.New(pcerr.FailedPrecondition, "NO_COMP_PLAN", "the organization has no comp plan in force")
	// ErrCompNeedsHostedBilling: self-hosted servers take entitlements from
	// the licence only (D85).
	ErrCompNeedsHostedBilling = pcerr.New(pcerr.FailedPrecondition, "COMP_NEEDS_HOSTED_BILLING",
		"complimentary plans are for hosted billing; self-hosted entitlements come from the licence")
)

// CompGrant is an operator's complimentary plan for one org (D12).
type CompGrant struct {
	PlanID string
	// Edition defaults to PlanID when that names an edition (team,
	// business, enterprise).
	Edition string
	Until   time.Time
	Reason  string
	// Operator names who ran the command (recorded as the actor).
	Operator string
}

func cleanReason(r string) (string, bool) {
	r = strings.TrimSpace(r)
	return r, r != "" && utf8.ValidString(r) && utf8.RuneCountInString(r) <= 500
}

// GrantComp gives org a complimentary plan until g.Until (HR-358): only
// from the operator command line, with a reason, at most a year, recorded
// in the org's evidence ledger and shown to the org. It overrides the
// billing state, which billing events keep updating (D87), and needs
// hosted billing: billing mode external (or off, which production refuses).
func (s *Service) GrantComp(ctx context.Context, org ids.OrgID, g CompGrant) error {
	if s.mode == ModeLicence {
		return ErrCompNeedsHostedBilling
	}
	if g.Edition == "" {
		g.Edition = g.PlanID
	}
	reason, ok := cleanReason(g.Reason)
	now := s.clock.Now()
	switch {
	case !ok, g.PlanID == "", !planIDPattern(g.PlanID), !ValidEdition(g.Edition) || g.Edition == EditionDevelopment,
		g.Edition == string(billing.Community), !g.Until.After(now), g.Until.Sub(now) > MaxComp,
		g.Operator == "" || len(g.Operator) > 200:
		return ErrInvalidComp
	}
	if org.IsZero() || org == ids.PlatformOrg {
		return ErrUnknownOrg
	}
	until := g.Until.UTC()
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if state, err := q.OrgState(ctx, org); db.IsNoRows(err) || (err == nil && state != "ACTIVE") {
			return ErrUnknownOrg
		} else if err != nil {
			return err
		}
		version, err := q.PutCompPlan(ctx, dbq.PutCompPlanParams{
			OrgID: org, CompPlanID: &g.PlanID, CompEdition: &g.Edition, CompUntil: &until, CompReason: &reason,
			CompBy: &g.Operator,
		})
		if err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "billing.comp_granted", Actor: evdomain.Actor{Type: "operator", ID: g.Operator}, Outcome: audit.Success,
			Object: &audit.Object{Type: "org", ID: org.String()},
			Details: map[string]string{
				"plan_id": g.PlanID, "edition": g.Edition, "until": until.Format(time.RFC3339), "reason": reason,
				"version": strconv.FormatInt(version, 10),
			},
		})
		if err != nil {
			return err
		}
		_, err = q.RefreshPlanLapse(ctx, org)
		return err
	})
}

// RevokeComp ends org's comp plan now (D34: with a reason); the org's plan
// falls back to its billing state at once, or reads as LAPSED without one
// (D87).
func (s *Service) RevokeComp(ctx context.Context, org ids.OrgID, reason, operator string) error {
	if s.mode == ModeLicence {
		return ErrCompNeedsHostedBilling
	}
	reason, ok := cleanReason(reason)
	if !ok || operator == "" || len(operator) > 200 {
		return ErrInvalidComp
	}
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		version, err := q.RevokeCompPlan(ctx, &reason, org)
		if db.IsNoRows(err) {
			return ErrNoComp
		} else if err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "billing.comp_revoked", Actor: evdomain.Actor{Type: "operator", ID: operator}, Outcome: audit.Success,
			Object:  &audit.Object{Type: "org", ID: org.String()},
			Details: map[string]string{"reason": reason, "version": strconv.FormatInt(version, 10)},
		})
		if err != nil {
			return err
		}
		_, err = q.RefreshPlanLapse(ctx, org)
		return err
	})
}

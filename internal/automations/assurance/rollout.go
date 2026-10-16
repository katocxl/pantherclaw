// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance

import (
	"context"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Rollout evidence and reports (D36, F743, F744) and status (D59, F283).

// Reasons a COHORT stage may not widen to FULL (ROLLOUT_UNVERIFIED).
const (
	UnverifiedNotCohort      = "NOT_IN_COHORT_STAGE"
	UnverifiedNoSuccess      = "NO_EVIDENCED_SUCCESS"
	UnverifiedAuthority      = "AUTHORITY_CHANGED_FAILURE"
	UnverifiedReconciliation = "OPEN_RECONCILIATION"
)

// RolloutEvidence implements autoports.RolloutEvidence (D36): in the
// current COHORT stage (since the authority row its apply created, D54)
// at least one LIVE execution of the version SUCCEEDED with completion
// evidence, none FAILED for AUTHORITY_CHANGED and none awaits
// reconciliation.
type RolloutEvidence struct{}

var _ autoports.RolloutEvidence = RolloutEvidence{}

// Verified implements autoports.RolloutEvidence.
func (RolloutEvidence) Verified(ctx context.Context, tx pgx.Tx, automation, version ids.UUID) (bool, []string, error) {
	q := dbq.New(tx)
	org, err := q.AssuranceVersionOrg(ctx, version)
	if db.IsNoRows(err) {
		return false, []string{UnverifiedNotCohort}, nil
	} else if err != nil {
		return false, nil, err
	}
	return verified(ctx, q, org, automation, version)
}

func verified(ctx context.Context, q *dbq.Queries, org ids.OrgID, automation, version ids.UUID) (bool, []string, error) {
	a, err := q.AssuranceAutomation(ctx, org, automation)
	if db.IsNoRows(err) {
		return false, []string{UnverifiedNotCohort}, nil
	} else if err != nil {
		return false, nil, err
	}
	if a.State != string(autodomain.StateActive) || a.Rollout == nil || *a.Rollout != string(autodomain.RolloutCohort) ||
		a.EnabledVersionID == nil || *a.EnabledVersionID != version {
		return false, []string{UnverifiedNotCohort}, nil
	}
	c, err := q.AssuranceActiveCeiling(ctx, org, automation)
	if db.IsNoRows(err) {
		return false, []string{UnverifiedNotCohort}, nil
	} else if err != nil {
		return false, nil, err
	}
	ev, err := q.AssuranceRolloutEvidence(ctx, dbq.AssuranceRolloutEvidenceParams{
		OrgID: org, AutomationID: automation, VersionID: version, Since: c.CreatedAt,
	})
	if err != nil {
		return false, nil, err
	}
	var reasons []string
	if ev.Evidenced == 0 {
		reasons = append(reasons, UnverifiedNoSuccess)
	}
	if ev.AuthorityFailed > 0 {
		reasons = append(reasons, UnverifiedAuthority)
	}
	if ev.Reconciling > 0 {
		reasons = append(reasons, UnverifiedReconciliation)
	}
	return len(reasons) == 0, reasons, nil
}

// RolloutReport is an automation's rollout stage and outcomes.
type RolloutReport struct {
	Stage           string
	Version         *ids.UUID
	Executions      map[string]int
	ShadowedEffects int
	WouldBeRefusals map[string]int
	FullVerified    bool
	Unverified      []string
}

// GetRolloutReport reports an automation's rollout (D36).
func (s *Service) GetRolloutReport(ctx context.Context, automation ids.UUID) (RolloutReport, error) {
	c, err := caller(ctx, td.PermAutomationRead)
	if err != nil {
		return RolloutReport{}, err
	}
	if err := s.edition(ctx, false); err != nil {
		return RolloutReport{}, err
	}
	out := RolloutReport{Executions: map[string]int{}, WouldBeRefusals: map[string]int{}}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := q.AssuranceAutomation(ctx, c.Org, automation)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if a.Rollout != nil {
			out.Stage = *a.Rollout
		}
		out.Version = a.EnabledVersionID
		if a.EnabledVersionID == nil {
			out.Unverified = []string{UnverifiedNotCohort}
			return nil
		}
		v := *a.EnabledVersionID
		counts, err := q.AssuranceExecutionCounts(ctx, c.Org, automation, v)
		if err != nil {
			return err
		}
		for _, x := range counts {
			out.Executions[x.Mode+":"+x.State] = int(x.N)
		}
		steps, err := q.AssuranceShadowSteps(ctx, c.Org, automation, v)
		if err != nil {
			return err
		}
		for _, x := range steps {
			if x.State == string(autodomain.StepShadowed) {
				out.ShadowedEffects += int(x.N)
			}
			if x.Decision == "REFUSED" {
				out.WouldBeRefusals[x.Reason] += int(x.N)
			}
		}
		out.FullVerified, out.Unverified, err = verified(ctx, q, c.Org, automation, v)
		return err
	}, db.ReadOnly())
	return out, err
}

// Budget is one ceiling cap for today (UTC) and its use.
type StatusBudget struct {
	Name, Limit, Used string
}

// Status is an automation's status (D59, F283).
type Status struct {
	State, Rollout  string
	NextRun         *time.Time
	LatestExecution *ids.UUID
	LatestState     string
	LatestEvidenced bool
	LatestEnded     *time.Time
	Budgets         []StatusBudget
	Queued, Waiting int
	PendingGates    int
	ReviewBy        *time.Time
}

// GetAutomationStatus returns an automation's status (D59).
func (s *Service) GetAutomationStatus(ctx context.Context, automation ids.UUID) (Status, error) {
	c, err := caller(ctx, td.PermAutomationRead)
	if err != nil {
		return Status{}, err
	}
	if err := s.edition(ctx, false); err != nil {
		return Status{}, err
	}
	var out Status
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := q.AssuranceAutomation(ctx, c.Org, automation)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		out.State = a.State
		if a.Rollout != nil {
			out.Rollout = *a.Rollout
		}
		if out.NextRun, err = q.AssuranceNextRun(ctx, c.Org, automation); err != nil && !db.IsNoRows(err) {
			return err
		}
		latest, err := q.AssuranceLatestOutcome(ctx, c.Org, automation)
		switch {
		case db.IsNoRows(err):
		case err != nil:
			return err
		default:
			out.LatestExecution, out.LatestState, out.LatestEvidenced, out.LatestEnded = &latest.ID, latest.State, latest.Evidenced,
				latest.EndedAt
		}
		b, err := q.AssuranceBacklog(ctx, c.Org, automation)
		if err != nil {
			return err
		}
		out.Queued, out.Waiting, out.PendingGates = int(b.Queued), int(b.Waiting), int(b.Gates)
		return s.budgets(ctx, q, c.Org, automation, &out)
	}, db.ReadOnly())
	return out, err
}

// budgets fills today's ceiling caps and use from the ACTIVE authority
// row's version.
func (s *Service) budgets(ctx context.Context, q *dbq.Queries, org ids.OrgID, automation ids.UUID, out *Status) error {
	ce, err := q.AssuranceActiveCeiling(ctx, org, automation)
	if db.IsNoRows(err) {
		return nil
	} else if err != nil {
		return err
	}
	out.ReviewBy = &ce.ReviewBy
	_, def, err := version(ctx, q, org, ce.VersionID)
	if err != nil || def.Authority.Ceiling == nil {
		return err
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return err
	}
	today := now.UTC().Truncate(24 * time.Hour)
	day := pgtype.Date{Time: today, Valid: true}
	usage, err := q.GetAutomationUsage(ctx, org, automation, day)
	if err != nil {
		return err
	}
	grants, runs := 0, 0
	for _, u := range usage {
		if u.Day.Time.Equal(today) {
			grants, runs = int(u.Grants), int(u.Runs)
		}
	}
	pd := def.Authority.Ceiling.PerDay
	out.Budgets = append(out.Budgets, StatusBudget{Name: "grants", Limit: itoa(pd.Grants), Used: itoa(grants)},
		StatusBudget{Name: "runs", Limit: itoa(pd.Runs), Used: itoa(runs)})
	spent, err := q.GetAutomationBudgetUsage(ctx, org, automation, day)
	if err != nil {
		return err
	}
	for _, m := range pd.Budget {
		used := "0"
		for _, b := range spent {
			if b.Day.Time.Equal(today) && b.Currency == m.Currency {
				used = b.Reserved.String()
			}
		}
		out.Budgets = append(out.Budgets, StatusBudget{Name: m.Currency, Limit: m.Amount, Used: used})
	}
	return nil
}

func itoa(n int) string { return strconv.Itoa(n) }

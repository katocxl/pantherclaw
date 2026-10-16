// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	agentsapp "github.com/katocxl/pantherclaw/internal/agents/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Ceiling revalidation reasons (stable codes).
const (
	ReasonApproverInactive   = "APPROVER_INACTIVE"
	ReasonApproverPermission = "APPROVER_PERMISSION"
	ReasonApproverCompromise = "APPROVER_COMPROMISED"
)

var (
	_ autoports.CeilingChecker = (*Service)(nil)
	_ grantsapp.Ceilings       = (*Service)(nil)
	_ runsapp.AutomationRuns   = (*Service)(nil)
)

// confirmerScopes is what a confirmer of a version (or an approver of its
// ceiling) must hold, from the kinds it uses (D7, HR-272).
func confirmerScopes(kinds []string) autodomain.ConfirmerScopes {
	d := autodomain.Definition{}
	for _, k := range kinds {
		d.Do = append(d.Do, autodomain.StepSpec{Step: k})
	}
	return d.RequiredConfirmerPermissions()
}

// qualifies checks one person against a version's confirmer requirements
// now (D7, HR-272, HR-273): an active person holding automation.publish at
// the org, every agent-path permission on every ceiling agent's path, every
// org permission at the org, and not marked compromised. It returns the
// stable reason when the person does not qualify.
func (s *Service) qualifies(ctx context.Context, ptx pgx.Tx, q *dbq.Queries, org ids.OrgID, user ids.UUID,
	scopes autodomain.ConfirmerScopes, agents []ids.UUID,
) (bool, string, error) {
	active, err := q.SubjectUserActive(ctx, org, user)
	if err != nil && !db.IsNoRows(err) {
		return false, "", err
	}
	if !active {
		return false, ReasonApproverInactive, nil
	}
	p := td.PrincipalRef{Kind: td.KindUser, ID: user}
	bs, err := tapp.Bindings(ctx, q, org, p)
	if err != nil {
		return false, "", err
	}
	subj := td.Subject{Org: org, Principal: p, Bindings: bs}
	if !subj.Can(td.PermAutomationPublish, td.OrgPath(org)) {
		return false, ReasonApproverPermission, nil
	}
	for _, perm := range scopes.Org {
		if !subj.Can(td.Permission(perm), td.OrgPath(org)) {
			return false, ReasonApproverPermission, nil
		}
	}
	for _, a := range agents {
		row, err := q.GetAgent(ctx, org, a)
		if db.IsNoRows(err) {
			return false, ReasonApproverPermission, nil
		} else if err != nil {
			return false, "", err
		}
		path, err := agentsapp.PathOf(ctx, q, row)
		if err != nil {
			return false, "", err
		}
		for _, perm := range scopes.AgentPaths {
			if !subj.Can(td.Permission(perm), path) {
				return false, ReasonApproverPermission, nil
			}
		}
	}
	if s.Compromise != nil {
		bad, err := s.Compromise.Compromised(ctx, ptx, org, user)
		if err != nil {
			return false, "", err
		}
		if bad {
			return false, ReasonApproverCompromise, nil
		}
	}
	return true, "", nil
}

// Check implements autoports.CeilingChecker: every approver of the ceiling
// still qualifies for the kinds its version uses.
func (s *Service) Check(ctx context.Context, tx pgx.Tx, c autodomain.CeilingCheck) (bool, string, error) {
	q := dbq.New(tx)
	scopes := confirmerScopes(c.Kinds)
	for _, u := range c.Approvers {
		ok, reason, err := s.qualifies(ctx, tx, q, c.Org, u, scopes, c.Agents)
		if err != nil || !ok {
			return ok, reason, err
		}
	}
	return true, "", nil
}

// ceilingOf builds the issuance ceiling of a definition for the grants
// service.
func ceilingOf(d *autodomain.Definition) (grantsapp.AutomationCeiling, error) {
	c := d.Authority.Ceiling
	if c == nil {
		return grantsapp.AutomationCeiling{}, grantsapp.ErrCeilingInactive
	}
	out := grantsapp.AutomationCeiling{
		AutomationName: d.Name, Agents: d.CeilingAgents(), Bounds: c.Bounds, Requirements: c.Requirements,
		TTL: c.PerGrant.TTL.D(), Limits: c.PerGrant.Limits, MinAttestation: c.PerGrant.MinAttestation,
		Delegation: gdomain.Delegation{Depth: c.Delegation.Depth, MaxChildren: c.Delegation.MaxChildren},
	}
	return out, nil
}

// principalOf is the principal a version declares for its automation.
func principalOf(d *autodomain.Definition, serviceAccount ids.UUID) gdomain.Principal {
	if u, ok := d.Authority.PrincipalUser(); ok {
		return gdomain.Principal{Kind: gdomain.PrincipalUser, ID: u.UUID()}
	}
	return gdomain.Principal{Kind: gdomain.PrincipalServiceAccount, ID: serviceAccount}
}

// liveCeiling loads the automation, its enabled version and its ACTIVE
// ceiling, and checks them for issuance (D9 steps 1–2, D54, D55).
func (s *Service) liveCeiling(ctx context.Context, tx db.TenantTx, org ids.OrgID, automation, version, ceiling, agent ids.UUID,
) (dbq.PcAutomation, *autodomain.Definition, dbq.GetActiveAutomationCeilingRow, error) {
	q := dbq.New(tx)
	var zero dbq.GetActiveAutomationCeilingRow
	a, err := loadAutomation(ctx, q, org, automation, false)
	if err != nil {
		return a, nil, zero, grantsapp.ErrCeilingInactive
	}
	switch {
	case a.State != string(autodomain.StateActive), a.EnabledVersionID == nil, *a.EnabledVersionID != version, a.Rollout == nil:
		return a, nil, zero, grantsapp.ErrCeilingInactive
	case *a.Rollout != string(autodomain.RolloutCohort) && *a.Rollout != string(autodomain.RolloutFull):
		return a, nil, zero, grantsapp.ErrCeilingInactive // SHADOW issues nothing (D54)
	case *a.Rollout == string(autodomain.RolloutCohort) && !agent.IsZero() && !slices.Contains(a.CohortAgents, agent):
		return a, nil, zero, pcerr.Wrap(grantsapp.ErrOutsideCeiling, pcerr.FailedPrecondition, "OUTSIDE_COHORT",
			"the agent is outside the cohort this version is rolled out to")
	}
	c, err := q.GetActiveAutomationCeiling(ctx, org, automation)
	switch {
	case db.IsNoRows(err):
		return a, nil, zero, grantsapp.ErrCeilingInactive
	case err != nil:
		return a, nil, zero, err
	case c.ID != ceiling, c.VersionID != version, !c.InReview:
		return a, nil, zero, grantsapp.ErrCeilingInactive
	}
	v, err := loadVersion(ctx, q, org, version, false)
	if err != nil {
		return a, nil, zero, err
	}
	d, err := definitionOf(v)
	if err != nil {
		return a, nil, zero, err
	}
	return a, d, c, nil
}

// IssueCeiling implements grantsapp.Ceilings. It writes nothing; a
// ceiling an approver no longer qualifies for returns ErrCeilingVoid and
// the engine voids it in its own transaction (VoidCeiling, D57).
func (s *Service) IssueCeiling(ctx context.Context, tx db.TenantTx, in grantsapp.AutomationIssue) (grantsapp.AutomationCeiling, error) {
	a, d, c, err := s.liveCeiling(ctx, tx, in.Org, in.Automation, in.Version, in.Ceiling, in.AgentID)
	if err != nil {
		return grantsapp.AutomationCeiling{}, err
	}
	ok, _, err := s.Check(ctx, tx.Pgx(), autodomain.CeilingCheck{
		Org: in.Org, Automation: a.ID, Ceiling: c.ID, Approvers: c.ApprovedBy, Agents: d.CeilingAgents(), Kinds: d.Kinds(),
	})
	if err != nil {
		return grantsapp.AutomationCeiling{}, err
	}
	if !ok {
		return grantsapp.AutomationCeiling{}, grantsapp.ErrCeilingVoid
	}
	out, err := ceilingOf(d)
	if err != nil {
		return out, err
	}
	out.ID, out.ServiceAccount, out.Approvers = c.ID, a.ServiceAccountID, c.ApprovedBy
	out.Principal = principalOf(d, a.ServiceAccountID)
	return out, nil
}

// errDryRun rolls back a dry-run reservation's savepoint.
var errDryRun = errors.New("automations: dry run")

// Reserve implements grantsapp.Ceilings: one grant and its budgets
// against today's caps, by conditional increments (D9 step 8).
func (s *Service) Reserve(ctx context.Context, tx db.TenantTx, in grantsapp.AutomationIssue, budgets map[string]money.Decimal, dryRun bool) error {
	q := dbq.New(tx)
	v, err := loadVersion(ctx, q, in.Org, in.Version, false)
	if err != nil {
		return err
	}
	d, err := definitionOf(v)
	if err != nil {
		return err
	}
	c := d.Authority.Ceiling
	if c == nil {
		return grantsapp.ErrCeilingInactive
	}
	reserve := func() error {
		if _, err := q.IncrementAutomationGrants(ctx, in.Org, in.Automation, int32(c.PerDay.Grants)); db.IsNoRows(err) { //nolint:gosec // ≤ 1000
			return grantsapp.ErrUsageExceeded
		} else if err != nil {
			return err
		}
		for cur, amount := range budgets {
			i := slices.IndexFunc(c.PerDay.Budget, func(m autodomain.Money) bool { return m.Currency == cur })
			if i < 0 {
				return grantsapp.ErrUsageExceeded // a currency without a daily budget is never spent
			}
			limit, err := money.Parse(c.PerDay.Budget[i].Amount)
			if err != nil {
				return err
			}
			if _, err := q.ReserveAutomationBudget(ctx, dbq.ReserveAutomationBudgetParams{
				OrgID: in.Org, AutomationID: in.Automation, Currency: cur, Amount: amount, MaxAmount: limit,
			}); db.IsNoRows(err) {
				return grantsapp.ErrUsageExceeded
			} else if err != nil {
				return err
			}
		}
		return nil
	}
	if !dryRun {
		return reserve()
	}
	err = tx.Savepoint(ctx, "automation_dry_reserve", func() error {
		if err := reserve(); err != nil {
			return err
		}
		return errDryRun
	})
	if errors.Is(err, errDryRun) {
		return nil
	}
	return err
}

// ReserveRun implements runsapp.AutomationRuns: one run against today's
// cap of the automation's enabled version.
func (s *Service) ReserveRun(ctx context.Context, tx db.TenantTx, org ids.OrgID, automation ids.UUID, dryRun bool) error {
	q := dbq.New(tx)
	a, err := loadAutomation(ctx, q, org, automation, false)
	if err != nil {
		return err
	}
	if a.EnabledVersionID == nil {
		return grantsapp.ErrCeilingInactive
	}
	v, err := loadVersion(ctx, q, org, *a.EnabledVersionID, false)
	if err != nil {
		return err
	}
	d, err := definitionOf(v)
	if err != nil {
		return err
	}
	if d.Authority.Ceiling == nil {
		return grantsapp.ErrCeilingInactive
	}
	reserve := func() error {
		_, err := q.IncrementAutomationRuns(ctx, org, automation, int32(d.Authority.Ceiling.PerDay.Runs)) //nolint:gosec // ≤ 1000
		if db.IsNoRows(err) {
			return grantsapp.ErrUsageExceeded
		}
		return err
	}
	if !dryRun {
		return reserve()
	}
	err = tx.Savepoint(ctx, "automation_dry_run", func() error {
		if err := reserve(); err != nil {
			return err
		}
		return errDryRun
	})
	if errors.Is(err, errDryRun) {
		return nil
	}
	return err
}

// dbNow reads the database clock.
func dbNow(ctx context.Context, q *dbq.Queries) (time.Time, error) { return q.DBNow(ctx) }

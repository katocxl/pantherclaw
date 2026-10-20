// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package onboarding computes an org's onboarding progress from its own
// records (G0 UI D15; F322, F325, F335, F336, F341; HR-362..364). Nothing a
// client says marks a step done: each step is the first record that shows
// it, read in the caller's org's tenant transaction, and simulated records
// (range agents, simulated runs and transactions) never count.
package onboarding

import (
	"context"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// StepID names a step (onboarding.proto StepId).
type StepID string

// Steps, in the order the console shows them.
const (
	StepSecurityKey      StepID = "SECURITY_KEY"
	StepInviteTeam       StepID = "INVITE_TEAM"
	StepGatewayEnrolled  StepID = "GATEWAY_ENROLLED"
	StepAgentEnrolled    StepID = "AGENT_ENROLLED"
	StepFirstDecision    StepID = "FIRST_DECISION"
	StepTestAllowed      StepID = "TEST_ALLOWED"
	StepTestHeld         StepID = "TEST_HELD"
	StepTestDenied       StepID = "TEST_DENIED"
	StepApprovalDecided  StepID = "APPROVAL_DECIDED"
	StepSuspensionTested StepID = "SUSPENSION_TESTED"
)

// Order is every step in order.
var Order = []StepID{
	StepSecurityKey, StepInviteTeam, StepGatewayEnrolled, StepAgentEnrolled, StepFirstDecision,
	StepTestAllowed, StepTestHeld, StepTestDenied, StepApprovalDecided, StepSuspensionTested,
}

// Evidence kinds (D58): each step's records, in the caller's org.
const (
	KindSecurityKey = "security_key" // a WebAuthn credential id
	KindInvitation  = "invitation"
	KindGateway     = "gateway"
	KindAgent       = "agent"
	KindDecision    = "decision" // the transaction whose decision receipt it is
	KindTransaction = "transaction"
	KindApproval    = "approval"   // an approval request id
	KindSuspension  = "suspension" // the agent change that suspended the agent
)

// Evidence names the record that completed a step.
type Evidence struct {
	Kind string
	ID   ids.UUID
}

// Step is one step's state: done when DoneAt is set.
type Step struct {
	ID       StepID
	DoneAt   *time.Time
	Evidence []Evidence
}

// Done reports whether the step is done.
func (s Step) Done() bool { return s.DoneAt != nil }

// Progress is every step.
type Progress struct {
	Steps    []Step
	Complete bool
}

// Service computes progress.
type Service struct{ pool *db.Pool }

// New returns the service.
func New(pool *db.Pool) *Service { return &Service{pool: pool} }

// GetProgress returns the caller's org's progress (onboarding.read). The
// security key step is the caller's own key.
func (s *Service) GetProgress(ctx context.Context) (Progress, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return Progress{}, err
	}
	if !c.CanAnywhere(td.PermOnboardingRead) {
		return Progress{}, td.ErrPermissionDenied(td.PermOnboardingRead)
	}
	steps := make(map[StepID]Step, len(Order))
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		org := c.Org
		set := func(id StepID, kind string, ref ids.UUID, at time.Time, err error) error {
			if db.IsNoRows(err) {
				return nil
			}
			if err != nil {
				return err
			}
			at = at.UTC()
			steps[id] = Step{ID: id, DoneAt: &at, Evidence: []Evidence{{Kind: kind, ID: ref}}}
			return nil
		}
		if c.Human() {
			r, err := q.OnboardingSecurityKey(ctx, org, c.Principal.ID)
			if err := set(StepSecurityKey, KindSecurityKey, r.ID, r.CreatedAt, err); err != nil {
				return err
			}
		}
		inv, err := q.OnboardingInvitation(ctx, org)
		if err := set(StepInviteTeam, KindInvitation, inv.ID, inv.CreatedAt, err); err != nil {
			return err
		}
		gw, err := q.OnboardingGateway(ctx, org)
		if err := set(StepGatewayEnrolled, KindGateway, gw.GatewayID, gw.IssuedAt, err); err != nil {
			return err
		}
		ag, err := q.OnboardingAgentInstance(ctx, org)
		if err := set(StepAgentEnrolled, KindAgent, ag.AgentID, ag.At, err); err != nil {
			return err
		}
		for _, d := range []struct {
			id        StepID
			kind      string
			decisions []string
		}{
			{StepFirstDecision, KindDecision, []string{"ALLOW", "ALLOW_WITH_OBLIGATIONS", "REQUIRE_APPROVAL", "REQUIRE_STEP_UP", "DENY", "CANNOT_AUTHORIZE"}},
			{StepTestAllowed, KindTransaction, []string{"ALLOW", "ALLOW_WITH_OBLIGATIONS"}},
			{StepTestDenied, KindTransaction, []string{"DENY"}},
		} {
			r, err := q.OnboardingDecision(ctx, org, d.decisions)
			if err := set(d.id, d.kind, r.ID, r.CreatedAt, err); err != nil {
				return err
			}
		}
		held, err := q.OnboardingHeld(ctx, org)
		if err := set(StepTestHeld, KindTransaction, held.ID, held.CreatedAt, err); err != nil {
			return err
		}
		if st, ok := steps[StepTestHeld]; ok && !held.RequestID.IsZero() {
			st.Evidence = append([]Evidence{{Kind: KindApproval, ID: held.RequestID}}, st.Evidence...)
			steps[StepTestHeld] = st
		}
		ap, err := q.OnboardingApprovalDecided(ctx, org)
		if err := set(StepApprovalDecided, KindApproval, ap.RequestID, ap.CreatedAt, err); err != nil {
			return err
		}
		su, err := q.OnboardingSuspension(ctx, org)
		return set(StepSuspensionTested, KindSuspension, su.SuspensionID, su.CreatedAt, err)
	}, db.ReadOnly())
	if err != nil {
		return Progress{}, err
	}
	out := Progress{Complete: true}
	for _, id := range Order {
		st, ok := steps[id]
		if !ok {
			st = Step{ID: id}
			if slices.Contains(Required, id) {
				out.Complete = false
			}
		}
		out.Steps = append(out.Steps, st)
	}
	return out, nil
}

// Required are the steps that complete onboarding (D79). Inviting a
// teammate and deciding an approval stay follow-up steps: a person alone
// in a new org cannot decide an approval of their own agent (owner
// exclusion and minimum ages stay in force).
var Required = []StepID{
	StepSecurityKey, StepGatewayEnrolled, StepAgentEnrolled, StepFirstDecision,
	StepTestAllowed, StepTestHeld, StepTestDenied, StepSuspensionTested,
}

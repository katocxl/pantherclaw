// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Workload is a PAP/1-authenticated workload instance acting in a run. The
// M3 identity checks establish it; it is never a tenancy caller, so it can
// reach no use case but Delegate (HR-161).
type Workload struct {
	Org        ids.OrgID
	InstanceID ids.UUID
	RunID      ids.UUID
}

// DelegateRequest asks to hand part of the workload's run grant to one of
// its child runs (F045, F055–F061). Bounds left open are inherited from the
// parent grant.
type DelegateRequest struct {
	ChildRunID     ids.UUID
	TaskRef        string
	ExpiresAt      time.Time // zero: as long as allowed
	Bounds         domain.Bounds
	Requirements   []domain.Requirement
	Limits         domain.Limits
	Delegation     domain.Delegation
	MinAttestation int
	// Flows are the data flows allowed after a sensitive read (G0 M16 D75).
	Flows []domain.FlowAllowance
}

// Delegate creates a delegated grant for a child run. Creating the child
// run (M3 StartChildRun) and delegating to it are separate calls. The child
// is checked against its parent grant, the guardrails and the caps
// (HR-045, HR-047); the repository repeats the fan-out check while the
// parent's row is locked and binds the grant to the child run.
func (s *Service) Delegate(ctx context.Context, w Workload, req DelegateRequest) (domain.Grant, error) {
	return s.delegateWith(ctx, repoDelegation{s}, w, req)
}

// delegateWith is Delegate over d: the repository's own transactions, or
// the caller's (DelegateTx). Every check is here, once.
func (s *Service) delegateWith(ctx context.Context, d delegation, w Workload, req DelegateRequest) (domain.Grant, error) {
	parentRun, err := d.run(ctx, w.Org, w.RunID)
	if err != nil {
		return domain.Grant{}, err
	}
	if !parentRun.Active || parentRun.InstanceID != w.InstanceID || parentRun.GrantID.IsZero() {
		return domain.Grant{}, ErrRunNotEligible
	}
	childRun, err := d.run(ctx, w.Org, req.ChildRunID)
	if err != nil {
		return domain.Grant{}, err
	}
	if !childRun.Active || childRun.ParentRunID != parentRun.ID || !childRun.GrantID.IsZero() {
		return domain.Grant{}, ErrRunNotEligible
	}
	parent, err := d.grant(ctx, w.Org, parentRun.GrantID)
	if err != nil {
		return domain.Grant{}, err
	}
	agent, err := d.agent(ctx, w.Org, childRun.AgentID)
	if err != nil {
		return domain.Grant{}, err
	}
	now := s.Clock.Now()
	expires := req.ExpiresAt
	if expires.IsZero() {
		expires = minTime(parent.ExpiresAt, now.Add(domain.MaxDelegatedLifetime))
	}
	child := domain.Grant{
		ID: domain.NewGrantID(), Org: w.Org, Revision: 1, State: domain.StateActive,
		AgentID: childRun.AgentID, Principal: parent.Principal, EnvironmentID: parent.EnvironmentID,
		TaskRef: req.TaskRef, NotBefore: maxTime(now.Add(-domain.IssueSkew), parent.NotBefore), ExpiresAt: expires,
		Bounds: req.Bounds.Inherit(parent.Bounds), Requirements: req.Requirements, Limits: req.Limits, Flows: req.Flows,
		Delegation: req.Delegation, MinAttestation: max(req.MinAttestation, parent.MinAttestation),
		Parent: parent.ID, Depth: parent.Depth + 1,
		Grantor: domain.Principal{Kind: domain.PrincipalInstance, ID: w.InstanceID},
		Basis:   fmt.Sprintf("delegation from grant %s revision %d in run %s", parent.ID, parent.Revision, parentRun.ID),
	}
	ic := domain.IssueContext{Now: now, Parent: &parent}
	if ic.Envelopes, err = d.envelopes(ctx, w.Org, scopesFor(agent, child.EnvironmentID, child.Principal)); err != nil {
		return domain.Grant{}, err
	}
	if ic.Lookup, err = s.lookup(ctx, w.Org, child.Bounds, child.Limits); err != nil {
		return domain.Grant{}, err
	}
	if ic.ActiveChildren, ic.TotalChildren, err = d.childCounts(ctx, w.Org, parent.ID, now); err != nil {
		return domain.Grant{}, err
	}
	if err := child.ValidateIssue(ic); err != nil {
		// A delegation beyond the parent grant or the guardrails is an agent
		// trying to widen its own authority (G0 M10 D59 H1, PN-006.3).
		s.refuseDelegation(ctx, w, parent, childRun.AgentID)
		return domain.Grant{}, apiError(err)
	}
	caps := domain.EffectiveCaps(ic.Envelopes)
	fan := Fanout{MaxActive: min(parent.Delegation.MaxChildren, caps.MaxChildren), MaxTotal: domain.MaxChildrenTotal}
	actor := evdomain.Actor{Type: string(domain.PrincipalInstance), ID: w.InstanceID.String()}
	ev := grantEvent(actor, "grant.delegated", child, map[string]string{
		"parent": parent.ID.String(), "parent_revision": fmt.Sprint(parent.Revision), "child_run": childRun.ID.String(),
	})
	if err := d.delegate(ctx, w.Org, &child, parent.Revision, childRun.ID, fan, ev); err != nil {
		return domain.Grant{}, apiError(err)
	}
	child.RevisedAt = now
	return child, nil
}

func (s *Service) run(ctx context.Context, org ids.OrgID, id ids.UUID) (Run, error) {
	r, err := s.Subjects.Run(ctx, org, id)
	if errors.Is(err, ErrNotFound) {
		return Run{}, ErrRunNotFound
	}
	return r, err
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// Delegation builds delegation settings from API values.
func Delegation(depth, maxChildren int32) domain.Delegation {
	return domain.Delegation{Depth: int(depth), MaxChildren: int(maxChildren)}
}

// refuseDelegation audits a refused delegation as grant.delegate_refused
// with the delegating instance as actor. The refusal stands whether or not
// the audit is written.
func (s *Service) refuseDelegation(ctx context.Context, w Workload, parent domain.Grant, child ids.UUID) {
	if s.Refusals == nil {
		return
	}
	_ = s.Refusals.RecordRefusal(context.WithoutCancel(ctx), w.Org, audit.Event{
		Name: "grant.delegate_refused", Actor: evdomain.Actor{Type: string(domain.PrincipalInstance), ID: w.InstanceID.String()},
		Outcome: audit.Denied, ReasonCode: "DELEGATION_EXCEEDS_PARENT", Object: &audit.Object{Type: "grant", ID: parent.ID.String()},
		Details: map[string]string{"agent": child.String(), "parent": parent.ID.String(), "attempted": "grant.delegate"},
	})
}

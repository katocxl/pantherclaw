// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package securitysteps

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Coverage reads one route's coverage as it reads now (coverage/app
// GetCoverage without a viewer): ENFORCED, PARTIAL, OBSERVE_ONLY or
// UNKNOWN, and the snapshot it was read from (zero when none).
type Coverage interface {
	RouteState(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent, connection ids.UUID, operation string) (string, ids.UUID, error)
}

// Owners resolves the people a security step assigns work to.
type Owners interface {
	// AgentOwner is the agent's owner, or nil when it has none.
	AgentOwner(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent ids.UUID) (*ids.UUID, error)
	// ConnectionOwner is the person who created the connection, or nil
	// when a service created it.
	ConnectionOwner(ctx context.Context, tx pgx.Tx, org ids.OrgID, connection ids.UUID) (*ids.UUID, error)
}

// Coverage states, strongest last (coverage/domain).
var coverageRank = map[string]int{"UNKNOWN": 1, "OBSERVE_ONLY": 2, "PARTIAL": 3, "ENFORCED": 4}

// ParamOperation is the trigger parameter that names the operation of a
// coverage.lost route: coverage events carry the agent and the connection
// as subjects and the operation as a field, which the template declares as
// a parameter (`from: operation`).
const ParamOperation = "operation"

// Bounds (D31).
const (
	MaxCoverageWait = 7 * 24 * time.Hour
	MaxAssignWithin = 7 * 24 * time.Hour
	MaxSummary      = 500
	MaxNextStep     = 500
)

// waitCoverage waits until the trigger's route (agent, connection,
// operation) is covered at min_state or better (D31, COVERAGE_RESTORED).
// It reads only.
type waitCoverage struct{ d Deps }

func (*waitCoverage) Kind() string { return autodomain.KindWaitCoverage }

type route struct {
	agent, connection ids.UUID
	operation         string
}

func (s *waitCoverage) check(sc autodomain.StepContext) (*autodomain.WaitCoverageWith, route, string) {
	w, ok := sc.With.(*autodomain.WaitCoverageWith)
	if !ok || (w.MinState != "ENFORCED" && w.MinState != "PARTIAL") || w.Timeout.D() <= 0 || w.Timeout.D() > MaxCoverageWait {
		return nil, route{}, ReasonBadWith
	}
	if !inScope(sc.Def, autodomain.KindWaitCoverage, autodomain.ScopeTriggerScope) {
		return nil, route{}, ReasonOutsideScope
	}
	var r route
	var okA, okC bool
	r.agent, okA = triggerSubject(sc, reflexdomain.SubjectAgent)
	r.connection, okC = triggerSubject(sc, reflexdomain.SubjectConnection)
	if v, ok := sc.Params[ParamOperation]; ok {
		r.operation = v.Text()
	}
	if !okA || !okC || r.operation == "" {
		return nil, route{}, ReasonNoSubject
	}
	return w, r, ""
}

func (s *waitCoverage) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	w, r, reason := s.check(sc)
	if reason != "" {
		return failed(reason)
	}
	if s.d.Coverage == nil {
		return unwired()
	}
	state, snapshot, err := s.d.Coverage.RouteState(ctx, tx, sc.Org, r.agent, r.connection, r.operation)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	out := map[string]string{"state": state, "agent": r.agent.String(), "connection": r.connection.String()}
	if coverageRank[state] >= coverageRank[w.MinState] && !snapshot.IsZero() {
		return autodomain.StepResult{
			State: autodomain.StepDone, Effect: autodomain.EffectNone, Output: out,
			Refs: []reflexdomain.EvidenceRef{ref(RefCoverage, snapshot)},
		}, nil
	}
	return waiting(out, nil, sc.Now.Add(pollEvery))
}

func (s *waitCoverage) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Run(ctx, tx, sc)
}

// Preview reads nothing that could change: it reports what it would wait
// for.
func (s *waitCoverage) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	w, r, reason := s.check(sc)
	if reason != "" {
		return previewRefused(reason)
	}
	return shadowed(map[string]string{"min_state": w.MinState, "agent": r.agent.String(), "connection": r.connection.String()})
}

// assignOwner records an owned failure for a person to act on (D31): the
// trigger agent's owner, the trigger connection's owner, or the
// automation's owner. It assigns work; it changes no authority.
type assignOwner struct{ d Deps }

func (*assignOwner) Kind() string { return autodomain.KindAssignOwner }

func (s *assignOwner) check(sc autodomain.StepContext) (*autodomain.AssignOwnerWith, string) {
	w, ok := sc.With.(*autodomain.AssignOwnerWith)
	if !ok || len([]rune(w.Summary)) > MaxSummary || len([]rune(w.NextStep)) > MaxNextStep ||
		w.Deadline.D() < 0 || w.Deadline.D() > MaxAssignWithin {
		return nil, ReasonBadWith
	}
	switch w.To {
	case autodomain.ScopeAgentOwner, autodomain.ScopeConnectionOwner, autodomain.ScopeOwner:
	default:
		return nil, ReasonBadWith
	}
	if !inScope(sc.Def, autodomain.KindAssignOwner, w.To) {
		return nil, ReasonOutsideScope
	}
	return w, ""
}

// owner resolves the person the work goes to.
func (s *assignOwner) owner(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext, to string) (*ids.UUID, string, error) {
	switch to {
	case autodomain.ScopeOwner:
		o := sc.Execution.Owner
		return &o, "", nil
	case autodomain.ScopeAgentOwner:
		agent, ok := triggerSubject(sc, reflexdomain.SubjectAgent)
		if !ok {
			return nil, ReasonNoSubject, nil
		}
		o, err := s.d.Owners.AgentOwner(ctx, tx, sc.Org, agent)
		return o, "", err
	default:
		conn, ok := triggerSubject(sc, reflexdomain.SubjectConnection)
		if !ok {
			return nil, ReasonNoSubject, nil
		}
		o, err := s.d.Owners.ConnectionOwner(ctx, tx, sc.Org, conn)
		return o, "", err
	}
}

func (s *assignOwner) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	w, reason := s.check(sc)
	if reason != "" {
		return failed(reason)
	}
	if s.d.Failures == nil || (w.To != autodomain.ScopeOwner && s.d.Owners == nil) {
		return unwired()
	}
	who, reason, err := s.owner(ctx, tx, sc, w.To)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	if reason != "" {
		return failed(reason)
	}
	if who == nil || who.IsZero() {
		return failed(ReasonNoOwner)
	}
	summary := strings.TrimSpace(w.Summary)
	if summary == "" {
		summary = "Automation " + sc.Execution.AutomationName + " assigned you follow-up work."
	}
	within := w.Deadline.D()
	if within <= 0 {
		within = MaxAssignWithin
	}
	owner := reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: who.String()}
	f, err := s.d.Failures.Report(ctx, tx, reflexdomain.Failure{
		Org: sc.Org, Kind: FailureAssigned, Summary: summary, NextStep: strings.TrimSpace(w.NextStep),
		Scope: clip(append([]reflexdomain.Subject{automationSubject(sc)}, sc.Execution.Trigger.Subjects...)),
		Owner: &owner, Deadline: sc.Now.Add(within), DedupeKey: idempotency(sc),
	})
	if err != nil {
		if r, ok := refusal(err); ok {
			return failed(r)
		}
		return autodomain.StepResult{}, err
	}
	return autodomain.StepResult{
		State: autodomain.StepDone, Effect: autodomain.EffectChanged,
		Output: map[string]string{OutFailure: f.String(), "owner": who.String()},
		Refs:   []reflexdomain.EvidenceRef{ref(RefFailure, f)},
	}, nil
}

func (s *assignOwner) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Run(ctx, tx, sc)
}

func (s *assignOwner) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	w, reason := s.check(sc)
	if reason != "" {
		return previewRefused(reason)
	}
	return shadowed(map[string]string{"to": w.To})
}

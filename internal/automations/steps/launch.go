// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package steps

import (
	"context"
	"encoding/json/v2"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// launchRun issues a fresh grant inside the ceiling, starts a run under it
// and hands the run to an enrolled agent as a launch, in one transaction
// (D25, D26, F1, F3). It waits until the launch is claimed (or its run
// binds an instance); past the claim deadline the launch expires and its
// grant is revoked (LAUNCH_NOT_CLAIMED). A retry issues a fresh grant, and
// never after the run bound (HR-280).
type launchRun struct{ d Deps }

func (*launchRun) Kind() string { return autodomain.KindLaunchRun }

// MaxRunParams bounds run_params (D25).
const MaxRunParams = 16

// plan is a launch's grant and run as the version and the trigger make
// them.
type plan struct {
	w       *autodomain.LaunchRunWith
	issue   LaunchIssue
	start   LaunchStart
	claim   time.Duration
	outside bool
}

func (s *launchRun) plan(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext, dry bool) (plan, string, error) {
	w, ok := sc.With.(*autodomain.LaunchRunWith)
	c := sc.Def.Authority.Ceiling
	if !ok || c == nil {
		return plan{}, ReasonBadWith, nil
	}
	agent := w.Agent.UUID()
	if !slices.ContainsFunc(c.Agents, func(a autodomain.RefID) bool { return a.UUID() == agent }) {
		return plan{}, "OUTSIDE_CEILING", nil
	}
	if len(w.RunParams) > MaxRunParams || len(w.TaskRef) > 256 || len(w.Calls) > 10 {
		return plan{}, ReasonBadWith, nil
	}
	p := plan{w: w, claim: autodomain.DefaultClaimWithin}
	if w.ClaimWithin > 0 {
		if w.ClaimWithin.D() > time.Hour {
			return plan{}, ReasonBadWith, nil
		}
		p.claim = w.ClaimWithin.D()
	}
	if s.d.Rollout != nil && sc.Mode == autodomain.ModeLive {
		rollout, cohort, err := s.d.Rollout.Cohort(ctx, tx, sc.Org, sc.Execution.Automation)
		if err != nil {
			return plan{}, "", err
		}
		if rollout == autodomain.RolloutCohort && !slices.Contains(cohort, agent) {
			p.outside = true
			return p, "", nil
		}
	}
	ttl := c.PerGrant.TTL.D()
	if w.TTL > 0 {
		if w.TTL.D() > ttl {
			return plan{}, ReasonBadWith, nil
		}
		ttl = w.TTL.D()
	}
	bounds := c.Bounds
	{
		g := w.Grant
		if g.Operations != nil {
			bounds.Operations = g.Operations
		}
		if g.Targets != nil {
			bounds.Targets = g.Targets
		}
		if g.Accounts != nil {
			bounds.Accounts = g.Accounts
		}
		if g.Destinations != nil {
			bounds.Destinations = g.Destinations
		}
		if g.Params != nil {
			bounds.Params = g.Params
		}
	}
	limits := c.PerGrant.Limits
	if w.Grant.Limits != nil {
		limits = *w.Grant.Limits
	}
	var instance *ids.UUID
	if w.Instance != nil {
		i := w.Instance.UUID()
		instance = &i
	}
	ex := sc.Execution
	p.issue = LaunchIssue{
		Org: sc.Org, Automation: ex.Automation, Version: ex.Version, Execution: ex.ID, Ceiling: ex.Ceiling,
		ServiceAccount: ex.ServiceAccount, Agent: agent, Instance: instance, Principal: ex.Principal, TaskRef: w.TaskRef,
		TTL: ttl, Bounds: bounds, Requirements: c.Requirements, Limits: limits, DryRun: dry,
	}
	p.start = LaunchStart{
		Org: sc.Org, Execution: ex.ID, ServiceAccount: ex.ServiceAccount, Agent: agent, Instance: instance,
		Principal: ex.Principal, TaskRef: w.TaskRef, TTL: ttl, DryRun: dry,
	}
	return p, "", nil
}

// Run implements autoports.Step.
func (s *launchRun) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	if s.d.Grants == nil || s.d.Runs == nil {
		return unwired()
	}
	p, reason, err := s.plan(ctx, tx, sc, false)
	if err != nil || reason != "" {
		return autodomain.StepResult{State: autodomain.StepFailed, Reason: reason, Effect: autodomain.EffectNone}, err
	}
	if p.outside {
		return autodomain.StepResult{
			State: autodomain.StepSkipped, Reason: autodomain.ReasonOutsideCohort,
			Effect: autodomain.EffectNone,
		}, nil
	}
	if p.w.Delivery == autodomain.DeliveryWebhook && (p.w.Destination == nil || s.d.Deliverer == nil ||
		!slices.Contains(sc.Def.Authority.Destinations, *p.w.Destination)) {
		return failed(autodomain.ReasonDestinationInactive)
	}
	grant, err := s.d.Grants.IssueForAutomation(ctx, tx, p.issue)
	if err != nil {
		if r, ok := refusal(err); ok {
			return failed(r)
		}
		return autodomain.StepResult{}, err
	}
	p.start.Grant = grant
	run, err := s.d.Runs.StartForAutomation(ctx, tx, p.start)
	if err != nil {
		if r, ok := refusal(err); ok {
			// The grant was issued in this transaction: revoke it at once.
			if _, rerr := s.d.Grants.RevokeForAutomation(ctx, tx, GrantRevoke{
				Org: sc.Org, Execution: sc.Execution.ID, Grant: &grant, Scope: autodomain.RevokeExecution, Reason: r,
			}); rerr != nil {
				return autodomain.StepResult{}, rerr
			}
			return autodomain.StepResult{
				State: autodomain.StepFailed, Reason: r, Effect: autodomain.EffectChanged,
				Output: map[string]string{OutGrant: grant.String()},
			}, nil
		}
		return autodomain.StepResult{}, err
	}
	calls, err := json.Marshal(callsOf(p.w.Calls), json.Deterministic(true))
	if err != nil {
		return autodomain.StepResult{}, err
	}
	params := p.w.RunParams
	if params == nil {
		params = map[string]string{}
	}
	runParams, err := json.Marshal(params, json.Deterministic(true))
	if err != nil {
		return autodomain.StepResult{}, err
	}
	launch := ids.NewV7()
	var dest *ids.UUID
	if p.w.Delivery == autodomain.DeliveryWebhook {
		d := p.w.Destination.UUID()
		dest = &d
	}
	delivery := autodomain.DeliveryPull
	if p.w.Delivery == autodomain.DeliveryWebhook {
		delivery = autodomain.DeliveryWebhook
	}
	if err := q(tx).InsertAutomationLaunch(ctx, dbq.InsertAutomationLaunchParams{
		OrgID: sc.Org, ID: launch, ExecutionID: sc.Execution.ID, AttemptID: attemptID(sc), AgentID: p.issue.Agent,
		InstanceID: p.issue.Instance, RunID: run, GrantID: grant, TaskRef: p.w.TaskRef, Delivery: delivery,
		DestinationID: dest, ClaimWithinS: int64(p.claim / time.Second), Calls: calls, RunParams: runParams,
	}); err != nil {
		return autodomain.StepResult{}, err
	}
	out := map[string]string{OutGrant: grant.String(), OutRun: run.String(), OutLaunch: launch.String()}
	if dest != nil {
		body, err := json.Marshal(WebhookLaunch{
			Type: "automation.launch", LaunchID: launch.String(), RunID: run.String(), AgentID: p.issue.Agent.String(),
			TaskRef: p.w.TaskRef, RunParams: params,
		}, json.Deterministic(true))
		if err != nil {
			return autodomain.StepResult{}, err
		}
		id, err := s.d.Deliverer.Deliver(ctx, tx, autodomain.Delivery{
			Org: sc.Org, Destination: *dest, Execution: sc.Execution.ID, Kind: autodomain.DeliveryLaunch, Body: body,
		})
		if err != nil {
			if r, ok := refusal(err); ok {
				return autodomain.StepResult{
					State: autodomain.StepFailed, Reason: r, Effect: autodomain.EffectChanged,
					Output: out,
				}, nil
			}
			return autodomain.StepResult{}, err
		}
		if _, err := q(tx).SetAutomationLaunchDelivery(ctx, &id, sc.Org, launch); err != nil {
			return autodomain.StepResult{}, err
		}
		out[OutDelivery] = id.String()
	}
	return autodomain.StepResult{
		State: autodomain.StepWaiting, Effect: autodomain.EffectChanged, Output: out,
		Refs:   []reflexdomain.EvidenceRef{ref(reflexdomain.EvidenceRun, run), ref(RefGrant, grant), ref(RefLaunch, launch)},
		WakeAt: sc.Now.Add(min(p.claim, engine.PollInterval)),
	}, nil
}

// WebhookLaunch is the body of a WEBHOOK launch: no secrets (D26).
type WebhookLaunch struct {
	Type      string            `json:"type"`
	LaunchID  string            `json:"launch_id"`
	RunID     string            `json:"run_id"`
	AgentID   string            `json:"agent_id"`
	TaskRef   string            `json:"task_ref"`
	RunParams map[string]string `json:"run_params"`
}

// StoredCall is a runner call as a launch stores it (D33).
type StoredCall struct {
	Connection string            `json:"connection"`
	Face       string            `json:"face"`
	Tool       string            `json:"tool,omitzero"`
	Method     string            `json:"method,omitzero"`
	Path       string            `json:"path,omitzero"`
	Input      map[string]string `json:"input,omitzero"`
}

func callsOf(cs []autodomain.RunnerCall) []StoredCall {
	out := make([]StoredCall, 0, len(cs))
	for _, c := range cs {
		out = append(out, StoredCall{
			Connection: c.Connection.String(), Face: c.Face, Tool: c.Tool, Method: c.Method,
			Path: c.Path, Input: c.Input,
		})
	}
	return out
}

// attemptID is the id of the attempt running the step; the engine passes
// it in the StepContext's own output under engine.OutputAttempt.
func attemptID(sc autodomain.StepContext) ids.UUID {
	id, _ := parseID(own(sc)[engine.OutputAttempt])
	return id
}

// Poll implements autoports.Step: claimed (or bound) → DONE; past the
// claim deadline → the launch expires, its grant is revoked, FAILED
// LAUNCH_NOT_CLAIMED.
func (s *launchRun) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	o := own(sc)
	launch, ok := parseID(o[OutLaunch])
	if !ok {
		return failed(ReasonBadWith)
	}
	l, err := q(tx).GetAutomationLaunch(ctx, sc.Org, launch)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	run := ref(reflexdomain.EvidenceRun, l.RunID)
	if l.RunBound && l.State == "PENDING" && l.RunInstanceID != nil {
		if _, err := q(tx).ClaimBoundAutomationLaunch(ctx, l.RunInstanceID, sc.Org, launch); err != nil {
			return autodomain.StepResult{}, err
		}
		l.State = "CLAIMED"
	}
	switch l.State {
	case "CLAIMED", "COMPLETED":
		out := clone(o)
		out[engine.OutputRunBound] = "true"
		return autodomain.StepResult{
			State: autodomain.StepDone, Effect: autodomain.EffectChanged, Output: out,
			Refs: []reflexdomain.EvidenceRef{run, ref(RefGrant, l.GrantID), ref(RefLaunch, launch)},
		}, nil
	case "PENDING":
		if !l.ClaimDue {
			return autodomain.StepResult{
				State: autodomain.StepWaiting, Effect: autodomain.EffectChanged, Output: o,
				WakeAt: minTime(l.ClaimDeadline, sc.Now.Add(engine.PollInterval)),
			}, nil
		}
		if _, err := q(tx).EndAutomationLaunch(ctx, "EXPIRED", sc.Org, launch); err != nil {
			return autodomain.StepResult{}, err
		}
	}
	if s.d.Grants != nil {
		if _, err := s.d.Grants.RevokeForAutomation(ctx, tx, GrantRevoke{
			Org: sc.Org, Execution: sc.Execution.ID, Grant: &l.GrantID, Scope: autodomain.RevokeExecution,
			Reason: autodomain.ReasonLaunchNotClaimed,
		}); err != nil {
			return autodomain.StepResult{}, err
		}
	}
	if s.d.Runs != nil {
		if err := s.d.Runs.EndForAutomation(ctx, tx, sc.Org, sc.Execution.ID, l.RunID, autodomain.ReasonLaunchNotClaimed); err != nil {
			return autodomain.StepResult{}, err
		}
	}
	return autodomain.StepResult{
		State: autodomain.StepFailed, Reason: autodomain.ReasonLaunchNotClaimed,
		Effect: autodomain.EffectChanged, Output: o, Refs: []reflexdomain.EvidenceRef{run},
	}, nil
}

// Preview implements autoports.Step: the issuance and the run start as
// dry runs (D9, D10; HR-288), nothing written.
func (s *launchRun) Preview(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	p, reason, err := s.plan(ctx, tx, sc, true)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	out := map[string]string{"shadow": "true", "decision": "ALLOWED"}
	if reason != "" {
		out["decision"], out["reason"] = "REFUSED", reason
		return autodomain.StepResult{State: autodomain.StepFailed, Reason: reason, Output: out}, nil
	}
	if p.outside {
		return autodomain.StepResult{State: autodomain.StepSkipped, Reason: autodomain.ReasonOutsideCohort}, nil
	}
	if s.d.Grants != nil && sc.Mode != autodomain.ModeTest {
		if _, err := s.d.Grants.IssueForAutomation(ctx, tx, p.issue); err != nil {
			if r, ok := refusal(err); ok {
				out["decision"], out["reason"] = "REFUSED", r
				return autodomain.StepResult{State: autodomain.StepFailed, Reason: r, Output: out}, nil
			}
			return autodomain.StepResult{}, err
		}
	}
	return shadowed(out)
}

func clone(m map[string]string) map[string]string {
	out := make(map[string]string, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package executionsrpc serves ExecutionService over Connect (G0 M11 part
// 2 D28, D29): the execution inspector, lookups and cancellation. The
// use cases check permissions (automation.read, automation.manage).
package executionsrpc

import (
	"context"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/pgengine"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Executions serves ExecutionService.
type Executions struct {
	pantherclawv1connect.UnimplementedExecutionServiceHandler
	e *pgengine.Engine
}

// New returns the ExecutionService handler.
func New(e *pgengine.Engine) *Executions { return &Executions{e: e} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func parseID(s string) (ids.UUID, error) {
	u, err := ids.ParseUUID(s)
	if err != nil || u.IsZero() {
		return ids.UUID{}, errInvalidID
	}
	return u, nil
}

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func tsp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return ts(*t)
}

func strp(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func idp(u *ids.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func idStrings(us []ids.UUID) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.String())
	}
	return out
}

func refs(rs []reflexdomain.EvidenceRef) []*pantherclawv1.AutomationEvidenceRef {
	out := make([]*pantherclawv1.AutomationEvidenceRef, 0, len(rs))
	for _, r := range rs {
		out = append(out, &pantherclawv1.AutomationEvidenceRef{Kind: r.Kind, Id: r.ID.String()})
	}
	return out
}

func execState(s string) pantherclawv1.AutomationExecutionState {
	return pantherclawv1.AutomationExecutionState(pantherclawv1.AutomationExecutionState_value["AUTOMATION_EXECUTION_STATE_"+s])
}

func modeOf(s string) pantherclawv1.AutomationExecutionMode {
	return pantherclawv1.AutomationExecutionMode(pantherclawv1.AutomationExecutionMode_value["AUTOMATION_EXECUTION_MODE_"+s])
}

func result(r *engine.Result) *pantherclawv1.AutomationExecutionResult {
	if r == nil {
		return nil
	}
	out := &pantherclawv1.AutomationExecutionResult{
		State: execState(string(r.State)), Reason: r.Reason, Changed: r.Changed, Unchanged: r.Unchanged, Unknown: r.Unknown,
		Compensated: r.Compensated, Cleanup: refs(r.Cleanup),
	}
	for _, f := range r.Finish {
		out.Finish = append(out.Finish, &pantherclawv1.AutomationFinishStatus{
			Step: f.Step, Condition: string(f.Condition), Met: f.Met, Refs: refs(f.Refs),
		})
	}
	for _, u := range r.Unresolved {
		out.Unresolved = append(out.Unresolved, &pantherclawv1.AutomationUnresolved{Step: u.Step, Kind: u.Kind, Detail: u.Detail})
	}
	return out
}

func execution(s pgengine.Summary) (*pantherclawv1.AutomationExecution, error) {
	r := s.Row
	out := &pantherclawv1.AutomationExecution{
		Id: r.ID.String(), AutomationId: r.AutomationID.String(), AutomationName: s.AutomationName,
		OwnerUserId: s.Owner.String(), VersionId: r.VersionID.String(), VersionNumber: s.VersionNumber,
		VersionDigest: s.VersionDigest, VersionSummary: s.VersionSummary, Mode: modeOf(r.Mode), State: execState(r.State),
		Reason: strp(r.Reason), CurrentStep: int32(r.CurrentStep), Compensating: r.Compensating,
		ServiceAccountId: r.ServiceAccountID.String(), CreatedAt: ts(r.CreatedAt), StartedAt: tsp(r.StartedAt),
		DeadlineAt: ts(r.DeadlineAt), EndedAt: tsp(r.EndedAt), CancelReason: strp(r.CancelReason),
		CancelRequestedBy: strp(r.CancelRequestedBy), Result: result(s.Result),
	}
	switch {
	case r.PrincipalUserID != nil:
		out.Principal = "user:" + r.PrincipalUserID.String()
	case r.PrincipalSaID != nil:
		out.Principal = "service_account:" + r.PrincipalSaID.String()
	}
	if r.StartedAt != nil {
		end := time.Now()
		if r.EndedAt != nil {
			end = *r.EndedAt
		}
		out.ElapsedSeconds = int64(end.Sub(*r.StartedAt) / time.Second)
	}
	params, err := pgengine.DecodeParams(r.Params)
	if err != nil {
		return nil, err
	}
	text := make(map[string]string, len(params))
	for k, v := range params {
		text[k] = v.Text()
	}
	out.Trigger = &pantherclawv1.AutomationExecutionTrigger{
		Id: r.TriggerID.String(), Kind: s.Trigger.Kind, Authenticity: s.Trigger.Authenticity,
		AuthenticityDetail: s.Trigger.Detail, SourceRef: s.Trigger.SourceRef, Params: text,
		RootTriggerId: r.RootTriggerID.String(), Ancestry: idStrings(r.Ancestry), Depth: int32(r.Depth),
		OccurredAt: ts(r.OccurredAt),
	}
	if s.Ceiling != nil {
		out.Ceiling = &pantherclawv1.AutomationExecutionCeiling{
			Id: s.Ceiling.ID.String(), ApprovedBy: idStrings(s.Ceiling.ApprovedBy), ReviewBy: ts(s.Ceiling.ReviewBy),
			State: s.Ceiling.State,
		}
	}
	return out, nil
}

func attempt(a engine.Attempt) *pantherclawv1.AutomationStepAttempt {
	decision := "ALLOWED"
	if a.Refused {
		decision = "REFUSED"
	}
	return &pantherclawv1.AutomationStepAttempt{
		Id: a.ID.String(), StepIndex: int32(a.Index), StepId: a.StepID, Attempt: int32(a.Number), Kind: a.Kind, //nolint:gosec // ≤ 40, ≤ 5
		Compensation: a.Compensation,
		State:        pantherclawv1.AutomationStepState(pantherclawv1.AutomationStepState_value["AUTOMATION_STEP_STATE_"+string(a.State)]),
		Decision:     decision, Reason: a.Reason, Output: a.Output, Refs: refs(a.Refs),
		Effect:    pantherclawv1.AutomationEffect(pantherclawv1.AutomationEffect_value["AUTOMATION_EFFECT_"+string(a.Effect)]),
		StartedAt: ts(a.StartedAt), EndedAt: ts(a.EndedAt), WakeAt: ts(a.WakeAt),
	}
}

// GetExecution implements ExecutionServiceHandler.
func (s *Executions) GetExecution(ctx context.Context, req *pantherclawv1.GetExecutionRequest) (*pantherclawv1.GetExecutionResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	in, err := s.e.GetExecution(ctx, id)
	if err != nil {
		return nil, err
	}
	ex, err := execution(in.Summary)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetExecutionResponse{Execution: ex}
	for _, a := range in.Attempts {
		out.Attempts = append(out.Attempts, attempt(a))
	}
	for _, g := range in.Grants {
		out.Grants = append(out.Grants, &pantherclawv1.AutomationExecutionGrant{
			Id: g.ID.String(), AgentId: g.Agent.String(), State: g.State, ExpiresAt: ts(g.ExpiresAt),
			BudgetLimit: g.BudgetLimit, BudgetUsed: g.BudgetUsed,
		})
	}
	for _, r := range in.Runs {
		out.Runs = append(out.Runs, &pantherclawv1.AutomationExecutionRun{
			Id: r.ID.String(), AgentId: r.AgentID.String(), InstanceId: idp(r.InstanceID), State: r.EffectiveState,
			ExpiresAt: ts(r.ExpiresAt), Transactions: r.Transactions, UnknownTransactions: r.Unknown,
		})
	}
	for _, l := range in.Launches {
		out.Launches = append(out.Launches, &pantherclawv1.AutomationLaunch{
			Id: l.ID.String(), AgentId: l.AgentID.String(), InstanceId: idp(l.InstanceID), RunId: l.RunID.String(),
			GrantId: l.GrantID.String(), Delivery: l.Delivery, DestinationId: idp(l.DestinationID),
			State:             pantherclawv1.AutomationLaunchState(pantherclawv1.AutomationLaunchState_value["AUTOMATION_LAUNCH_STATE_"+l.State]),
			ClaimedInstanceId: idp(l.ClaimedInstanceID), ClaimedAt: tsp(l.ClaimedAt), ClaimDeadline: ts(l.ClaimDeadline),
			CompletedAt: tsp(l.CompletedAt), TaskRef: l.TaskRef,
			Outcome: pantherclawv1.AutomationLaunchOutcome(
				pantherclawv1.AutomationLaunchOutcome_value["AUTOMATION_LAUNCH_OUTCOME_"+strp(l.Outcome)]),
		})
	}
	for _, g := range in.Gates {
		out.Gates = append(out.Gates, &pantherclawv1.AutomationGate{
			RequestId: g.Request.String(), StepId: g.Step, State: g.State, DeadlineAt: ts(g.Deadline),
			ApprovalsNeeded: int32(g.Needed), Approvals: int32(g.Approvals), //nolint:gosec // ≤ 2
		})
	}
	for _, d := range in.Deliveries {
		out.Deliveries = append(out.Deliveries, &pantherclawv1.AutomationExecutionDelivery{
			Id: d.ID.String(), DestinationId: d.DestinationID.String(), Kind: d.Kind, State: d.State, Attempts: d.Attempts,
			DeliveredAt: tsp(d.DeliveredAt),
		})
	}
	return out, nil
}

// ListExecutions implements ExecutionServiceHandler.
func (s *Executions) ListExecutions(ctx context.Context, req *pantherclawv1.ListExecutionsRequest) (*pantherclawv1.ListExecutionsResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	f := pgengine.ExecutionFilter{}
	if req.GetAutomationId() != "" {
		if f.Automation, err = parseID(req.GetAutomationId()); err != nil {
			return nil, err
		}
	}
	for _, st := range req.GetStates() {
		f.States = append(f.States, autodomain.ExecutionState(strings.TrimPrefix(st.String(), "AUTOMATION_EXECUTION_STATE_")))
	}
	if m := req.GetMode(); m != pantherclawv1.AutomationExecutionMode_AUTOMATION_EXECUTION_MODE_UNSPECIFIED {
		f.Mode = autodomain.Mode(strings.TrimPrefix(m.String(), "AUTOMATION_EXECUTION_MODE_"))
	}
	if req.GetSince() != nil {
		f.Since = req.GetSince().AsTime()
	}
	if req.GetUntil() != nil {
		f.Until = req.GetUntil().AsTime()
	}
	list, next, err := s.e.ListExecutions(ctx, pr, f)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListExecutionsResponse{NextPageToken: next}
	for _, x := range list {
		ex, err := execution(x)
		if err != nil {
			return nil, err
		}
		ex.Result = nil
		out.Executions = append(out.Executions, ex)
	}
	return out, nil
}

// LookupExecution implements ExecutionServiceHandler.
func (s *Executions) LookupExecution(ctx context.Context, req *pantherclawv1.LookupExecutionRequest) (*pantherclawv1.LookupExecutionResponse, error) {
	kind, raw := pgengine.LookupRun, req.GetRunId()
	switch {
	case req.GetGrantId() != "":
		kind, raw = pgengine.LookupGrant, req.GetGrantId()
	case req.GetTransactionId() != "":
		kind, raw = pgengine.LookupTransaction, req.GetTransactionId()
	}
	id, err := parseID(raw)
	if err != nil {
		return nil, err
	}
	x, err := s.e.LookupExecution(ctx, kind, id)
	if err != nil {
		return nil, err
	}
	ex, err := execution(x)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.LookupExecutionResponse{Execution: ex}, nil
}

func effect(e pgengine.CancelEffect) *pantherclawv1.AutomationCancelEffect {
	return &pantherclawv1.AutomationCancelEffect{
		ExecutionsAffected: idStrings(e.Executions), GrantsRevoked: idStrings(e.Grants), RunsEnded: idStrings(e.Runs),
		LaunchesCancelled: idStrings(e.Launches), GatesCancelled: idStrings(e.Gates), DeliveriesCancelled: idStrings(e.Deliveries),
		DeliveriesNotVerified: idStrings(e.DeliveriesNotVerified),
	}
}

// CancelExecution implements ExecutionServiceHandler.
func (s *Executions) CancelExecution(ctx context.Context, req *pantherclawv1.CancelExecutionRequest) (*pantherclawv1.CancelExecutionResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	x, eff, err := s.e.CancelExecution(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	ex, err := execution(x)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CancelExecutionResponse{Execution: ex, Effect: effect(eff)}, nil
}

// CancelActiveExecutions implements ExecutionServiceHandler.
func (s *Executions) CancelActiveExecutions(ctx context.Context, req *pantherclawv1.CancelActiveExecutionsRequest) (*pantherclawv1.CancelActiveExecutionsResponse, error) {
	id, err := parseID(req.GetAutomationId())
	if err != nil {
		return nil, err
	}
	eff, err := s.e.CancelActiveExecutions(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CancelActiveExecutionsResponse{Effect: effect(eff)}, nil
}

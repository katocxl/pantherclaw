// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package responserpc

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
)

// errArgument reports a malformed id or digest the validator let through.
var errArgument = pcerr.New(pcerr.InvalidArgument, "INVALID_ARGUMENT", "an id or digest does not parse")

// ResponseHandler serves ResponseService (G0 M10 D21–D26).
type ResponseHandler struct {
	pantherclawv1connect.UnimplementedResponseServiceHandler
	r *rapp.Response
}

// NewResponse returns the ResponseService handler.
func NewResponse(r *rapp.Response) *ResponseHandler { return &ResponseHandler{r: r} }

var _ pantherclawv1connect.ResponseServiceHandler = (*ResponseHandler)(nil)

func subject(s *pantherclawv1.ResponseSubject) reflexdomain.Subject {
	if s == nil {
		return reflexdomain.Subject{}
	}
	return reflexdomain.Subject{Type: reflexdomain.SubjectType(s.GetType()), ID: s.GetId()}
}

func optUUID(s *string) (*ids.UUID, error) {
	if s == nil {
		return nil, nil
	}
	u, err := ids.ParseUUID(*s)
	if err != nil {
		return nil, errArgument
	}
	return &u, nil
}

func uuid(s string) (ids.UUID, error) {
	u, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errArgument
	}
	return u, nil
}

func digest(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, errArgument
	}
	return b, nil
}

func strings(xs []ids.UUID) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = x.String()
	}
	return out
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func uuidString(p *ids.UUID) string {
	if p == nil {
		return ""
	}
	return p.String()
}

// PreviewContainment implements ResponseServiceHandler.
func (h *ResponseHandler) PreviewContainment(ctx context.Context, req *pantherclawv1.PreviewContainmentRequest) (*pantherclawv1.PreviewContainmentResponse, error) {
	p, err := h.r.PreviewContainment(ctx, subject(req.GetScope()), req.GetControl(), req.GetOperation())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.PreviewContainmentResponse{
		Narrow: p.Narrow, RunIds: strings(p.Runs), RunsOverLimit: p.RunsOver, AgentIds: strings(p.Agents), WaitingApprovals: p.Waiting,
		GatewayIds: strings(p.Gateways), AlternativePaths: p.Alternatives, Unknown: p.Unknown, PreviewDigest: hex.EncodeToString(p.Digest),
		ReachNote: p.ReachNote,
	}
	if r := p.Reach; r != nil {
		reach := &pantherclawv1.ContainmentReach{
			ResourcesBefore: int32(r.Before.Resources), ResourcesAfter: int32(r.After.Resources), //nolint:gosec // bounded counts
			UsableBefore: int32(r.Before.Usable), UsableAfter: int32(r.After.Usable), //nolint:gosec // bounded counts
			Stale: r.Stale, Note: r.Note,
		}
		for _, d := range r.Disruption {
			reach.Disruption = append(reach.Disruption, &pantherclawv1.ResponseSubject{Type: string(d.Type), Id: d.ID})
		}
		out.Reach = reach
	}
	return out, nil
}

// Contain implements ResponseServiceHandler.
func (h *ResponseHandler) Contain(ctx context.Context, req *pantherclawv1.ContainRequest) (*pantherclawv1.ContainResponse, error) {
	caseID, err := optUUID(req.CaseId)
	if err != nil {
		return nil, err
	}
	incidentID, err := optUUID(req.IncidentId)
	if err != nil {
		return nil, err
	}
	d, err := digest(req.GetPreviewDigest())
	if err != nil {
		return nil, err
	}
	in := rapp.ContainInput{
		Scope: subject(req.GetScope()), Control: req.GetControl(), Operation: req.GetOperation(), Reason: req.GetReason(),
		CaseID: caseID, IncidentID: incidentID, PreviewDigest: d, SkipPreview: req.GetSkipPreview(), SkipReason: req.GetSkipReason(),
		Idempotency: req.GetIdempotencyKey(),
	}
	if req.ExpireTime != nil {
		t := req.GetExpireTime().AsTime()
		in.ExpiresAt = &t
	}
	res, err := h.r.Contain(ctx, in)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ContainResponse{ActionId: res.ActionID.String(), Status: res.Status}, nil
}

// ProposeResponse implements ResponseServiceHandler.
func (h *ResponseHandler) ProposeResponse(ctx context.Context, req *pantherclawv1.ProposeResponseRequest) (*pantherclawv1.ProposeResponseResponse, error) {
	opts, err := h.r.ProposeResponse(ctx, subject(req.GetSubject()))
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ProposeResponseResponse{}
	for _, o := range opts {
		out.Options = append(out.Options, &pantherclawv1.ResponseOption{
			Kind: o.Kind, Scope: &pantherclawv1.ResponseSubject{Type: string(o.Scope.Type), Id: o.Scope.ID}, Control: o.Control,
			Narrow: o.Narrow, Rationale: o.Rationale,
		})
	}
	return out, nil
}

// TerminateRun implements ResponseServiceHandler.
func (h *ResponseHandler) TerminateRun(ctx context.Context, req *pantherclawv1.TerminateRunRequest) (*pantherclawv1.TerminateRunResponse, error) {
	run, err := uuid(req.GetRunId())
	if err != nil {
		return nil, err
	}
	caseID, err := optUUID(req.CaseId)
	if err != nil {
		return nil, err
	}
	incidentID, err := optUUID(req.IncidentId)
	if err != nil {
		return nil, err
	}
	res, err := h.r.Terminate(ctx, run, req.GetReason(), caseID, incidentID)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.TerminateRunResponse{ActionId: res.ActionID.String(), Status: res.Status}, nil
}

// PreviewCredentialChange implements ResponseServiceHandler.
func (h *ResponseHandler) PreviewCredentialChange(ctx context.Context, req *pantherclawv1.PreviewCredentialChangeRequest) (*pantherclawv1.PreviewCredentialChangeResponse, error) {
	conn, err := uuid(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	p, err := h.r.PreviewCredentialChange(ctx, conn, req.GetVersion())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.PreviewCredentialChangeResponse{
		Kind: p.Kind, State: p.State, GatewayId: p.Gateway.String(), AgentIds: strings(p.Agents), EveryAgent: p.EveryAgent,
		RunIds: strings(p.Runs), RunsOverLimit: p.RunsOver, SharedConnectionIds: strings(p.Shared), Unknown: p.Unknown,
		PreviewDigest: hex.EncodeToString(p.Digest),
	}, nil
}

func (h *ResponseHandler) change(ctx context.Context, conn string, version int32, reason, dig string, caseID, incidentID *string, rotate bool) (
	reflexdomain.ContainResult, error,
) {
	c, err := uuid(conn)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	d, err := digest(dig)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	cs, err := optUUID(caseID)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	is, err := optUUID(incidentID)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	return h.r.ChangeCredential(ctx, rapp.CredentialChange{
		Connection: c, Version: version, Reason: reason, PreviewDigest: d, CaseID: cs, IncidentID: is,
	}, rotate)
}

// RevokeSealedCredential implements ResponseServiceHandler.
func (h *ResponseHandler) RevokeSealedCredential(ctx context.Context, req *pantherclawv1.RevokeSealedCredentialRequest) (*pantherclawv1.RevokeSealedCredentialResponse, error) {
	res, err := h.change(ctx, req.GetConnectionId(), req.GetVersion(), req.GetReason(), req.GetPreviewDigest(), req.CaseId, req.IncidentId, false)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeSealedCredentialResponse{ActionId: res.ActionID.String(), Status: res.Status}, nil
}

// RotateSealedCredential implements ResponseServiceHandler.
func (h *ResponseHandler) RotateSealedCredential(ctx context.Context, req *pantherclawv1.RotateSealedCredentialRequest) (*pantherclawv1.RotateSealedCredentialResponse, error) {
	res, err := h.change(ctx, req.GetConnectionId(), req.GetVersion(), req.GetReason(), req.GetPreviewDigest(), req.CaseId, req.IncidentId, true)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RotateSealedCredentialResponse{ActionId: res.ActionID.String(), Status: res.Status}, nil
}

// RequestControl implements ResponseServiceHandler.
func (h *ResponseHandler) RequestControl(ctx context.Context, req *pantherclawv1.RequestControlRequest) (*pantherclawv1.RequestControlResponse, error) {
	res, paths, err := h.r.RequestControl(ctx, rapp.SOARRequest{
		Key: req.GetIdempotencyKey(), Scope: subject(req.GetScope()), Control: req.GetControl(), Operation: req.GetOperation(),
		Reason: req.GetReason(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RequestControlResponse{ActionId: res.ActionID.String(), Result: res.Result, Paths: pathsOf(paths), Replayed: res.Replayed, Reason: res.Reason}, nil
}

func pathsOf(ps []rapp.PathView) []*pantherclawv1.ResponsePath {
	out := make([]*pantherclawv1.ResponsePath, 0, len(ps))
	for _, p := range ps {
		v := &pantherclawv1.ResponsePath{
			Type: p.Type, SubjectType: p.SubjectType, SubjectId: p.SubjectID, Material: p.Material, Control: p.Control, Status: p.Status,
			Evidence: p.Evidence, Failure: p.Failure, UnsupportedReason: p.Unsupported, CancelCapability: p.Cancel,
		}
		if p.Confirmed != nil {
			v.ConfirmTime = timestamppb.New(*p.Confirmed)
		}
		out = append(out, v)
	}
	return out
}

func testsOf(ts []*pantherclawv1.RestorationTestAction) ([]rapp.TestAction, error) {
	out := make([]rapp.TestAction, 0, len(ts))
	for _, t := range ts {
		id, err := uuid(t.GetTransactionId())
		if err != nil {
			return nil, err
		}
		out = append(out, rapp.TestAction{Transaction: id, Evaluation: int(t.GetEvaluation()), Expect: t.GetExpect()})
	}
	return out, nil
}

func uuids(xs []string) ([]ids.UUID, error) {
	out := make([]ids.UUID, 0, len(xs))
	for _, x := range xs {
		u, err := uuid(x)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

func preconditionsOf(ps []rapp.Precondition) []*pantherclawv1.RestorationPrecondition {
	out := make([]*pantherclawv1.RestorationPrecondition, 0, len(ps))
	for _, p := range ps {
		out = append(out, &pantherclawv1.RestorationPrecondition{Check: p.Check, Subject: p.Subject, State: p.State, Detail: p.Detail})
	}
	return out
}

// RequestRestoration implements ResponseServiceHandler.
func (h *ResponseHandler) RequestRestoration(ctx context.Context, req *pantherclawv1.RequestRestorationRequest) (*pantherclawv1.RequestRestorationResponse, error) {
	controls, err := uuids(req.GetControlIds())
	if err != nil {
		return nil, err
	}
	r := rapp.RestorationRequest{Controls: controls, Reason: req.GetReason()}
	for _, st := range req.GetStages() {
		cs, err := uuids(st.GetControlIds())
		if err != nil {
			return nil, err
		}
		tests, err := testsOf(st.GetTests())
		if err != nil {
			return nil, err
		}
		r.Stages = append(r.Stages, rapp.StageSpec{Controls: cs, Tests: tests})
	}
	plan, pre, err := h.r.RequestRestoration(ctx, r)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RequestRestorationResponse{PlanId: plan.String(), Preconditions: preconditionsOf(pre)}, nil
}

// DecideRestoration implements ResponseServiceHandler.
func (h *ResponseHandler) DecideRestoration(ctx context.Context, req *pantherclawv1.DecideRestorationRequest) (*pantherclawv1.DecideRestorationResponse, error) {
	plan, err := uuid(req.GetPlanId())
	if err != nil {
		return nil, err
	}
	state, pre, err := h.r.DecideRestoration(ctx, plan, req.GetDecision() == "APPROVE")
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DecideRestorationResponse{State: state, Preconditions: preconditionsOf(pre)}, nil
}

func resultsOf(rs []rapp.TestResult) []*pantherclawv1.RestorationTestResult {
	out := make([]*pantherclawv1.RestorationTestResult, 0, len(rs))
	for _, r := range rs {
		out = append(out, &pantherclawv1.RestorationTestResult{
			Test: &pantherclawv1.RestorationTestAction{
				TransactionId: r.Transaction.String(), Evaluation: int32(r.Evaluation), Expect: r.Expect, //nolint:gosec // 1..64
			},
			Decision: r.Decision, Reason: r.Reason, Complete: r.Complete, Passed: r.Passed,
		})
	}
	return out
}

// ApplyRestorationStage implements ResponseServiceHandler.
func (h *ResponseHandler) ApplyRestorationStage(ctx context.Context, req *pantherclawv1.ApplyRestorationStageRequest) (*pantherclawv1.ApplyRestorationStageResponse, error) {
	plan, err := uuid(req.GetPlanId())
	if err != nil {
		return nil, err
	}
	state, results, err := h.r.ApplyRestorationStage(ctx, plan, req.GetOrdinal())
	if err != nil {
		return nil, err
	}
	applied := true
	for _, r := range results {
		applied = applied && r.Passed
	}
	return &pantherclawv1.ApplyRestorationStageResponse{State: state, Results: resultsOf(results), Applied: applied}, nil
}

// DecideContainmentHold implements ResponseServiceHandler.
func (h *ResponseHandler) DecideContainmentHold(ctx context.Context, req *pantherclawv1.DecideContainmentHoldRequest) (*pantherclawv1.DecideContainmentHoldResponse, error) {
	txn, err := uuid(req.GetTransactionId())
	if err != nil {
		return nil, err
	}
	page, err := h.r.DecideContainmentHold(ctx, txn, req.GetDecision() == "APPROVE", req.GetNote())
	switch {
	case errors.Is(err, rapp.ErrApproveOnPage):
		return &pantherclawv1.DecideContainmentHoldResponse{Outcome: "APPROVE_ON_PAGE", PageUrl: page}, nil
	case err != nil:
		return nil, err
	}
	return &pantherclawv1.DecideContainmentHoldResponse{Outcome: "DECLINED"}, nil
}

func actionOf(a dbq.PcResponseAction) *pantherclawv1.ResponseAction {
	out := &pantherclawv1.ResponseAction{
		Id: a.ID.String(), Kind: a.Kind, ScopeType: a.ScopeType, ScopeId: a.ScopeID, Control: deref(a.Control), Operation: deref(a.Operation),
		Reason: a.Reason, CaseId: uuidString(a.CaseID), IncidentId: uuidString(a.IncidentID), Actor: a.Actor, Source: a.Source,
		Status: a.Status, FutureConfirmed: a.FutureConfirmed, Epoch: a.Epoch.Int64, PreviewDigest: hex.EncodeToString(a.PreviewDigest),
		PreviewSkipped: a.SkipPreview, RequestTime: timestamppb.New(a.RequestedAt),
	}
	if a.SettledAt != nil {
		out.SettleTime = timestamppb.New(*a.SettledAt)
	}
	var summary map[string]any
	if json.Unmarshal(a.PreviewSummary, &summary) == nil && len(summary) > 0 {
		out.PreviewSummary = map[string]string{}
		for k, v := range summary {
			b, _ := json.Marshal(v)
			out.PreviewSummary[k] = string(b)
		}
	}
	var hist []struct {
		Transaction string `json:"transaction"`
		Permit      string `json:"permit"`
	}
	if json.Unmarshal(a.HistoricalOpen, &hist) == nil {
		for _, x := range hist {
			out.HistoricalOpen = append(out.HistoricalOpen, &pantherclawv1.HistoricalItem{TransactionId: x.Transaction, PermitState: x.Permit})
		}
	}
	return out
}

func controlOf(c dbq.PcContainmentControl) *pantherclawv1.ContainmentControl {
	out := &pantherclawv1.ContainmentControl{
		Id: c.ID.String(), ActionId: c.ActionID.String(), ScopeType: c.ScopeType, ScopeId: c.ScopeID, Control: c.Control,
		Operation: deref(c.Operation), Reason: c.Reason, CreatedBy: c.CreatedBy, CreateTime: timestamppb.New(c.CreatedAt),
		LiftedBy: deref(c.LiftedBy), RestorationId: uuidString(c.RestorationID),
	}
	if c.ExpiresAt != nil {
		out.ExpireTime = timestamppb.New(*c.ExpiresAt)
	}
	if c.LiftedAt != nil {
		out.LiftTime = timestamppb.New(*c.LiftedAt)
	}
	return out
}

// GetResponseAction implements ResponseServiceHandler.
func (h *ResponseHandler) GetResponseAction(ctx context.Context, req *pantherclawv1.GetResponseActionRequest) (*pantherclawv1.GetResponseActionResponse, error) {
	id, err := uuid(req.GetActionId())
	if err != nil {
		return nil, err
	}
	v, err := h.r.GetAction(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetResponseActionResponse{Action: actionOf(v.Action), Paths: pathsOf(v.Paths)}
	for _, c := range v.Controls {
		out.Controls = append(out.Controls, controlOf(c))
	}
	return out, nil
}

func pageSize(n int32) int32 {
	if n <= 0 || n > 200 {
		return 50
	}
	return n
}

// ListResponseActions implements ResponseServiceHandler.
func (h *ResponseHandler) ListResponseActions(ctx context.Context, req *pantherclawv1.ListResponseActionsRequest) (*pantherclawv1.ListResponseActionsResponse, error) {
	caseID, err := optUUID(req.CaseId)
	if err != nil {
		return nil, err
	}
	incidentID, err := optUUID(req.IncidentId)
	if err != nil {
		return nil, err
	}
	var before *ids.UUID
	if t := req.GetPageToken(); t != "" {
		u, err := uuid(t)
		if err != nil {
			return nil, err
		}
		before = &u
	}
	size := pageSize(req.GetPageSize())
	var scope *reflexdomain.Subject
	if s := req.GetScope(); s != nil {
		sub := subject(s)
		scope = &sub
	}
	rows, err := h.r.ListActions(ctx, caseID, incidentID, scope, before, size+1)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListResponseActionsResponse{}
	if len(rows) > int(size) {
		rows = rows[:size]
		out.NextPageToken = rows[len(rows)-1].ID.String()
	}
	for _, a := range rows {
		out.Actions = append(out.Actions, actionOf(a))
	}
	return out, nil
}

// ListContainmentControls implements ResponseServiceHandler.
func (h *ResponseHandler) ListContainmentControls(ctx context.Context, req *pantherclawv1.ListContainmentControlsRequest) (*pantherclawv1.ListContainmentControlsResponse, error) {
	rows, err := h.r.ListControls(ctx, req.GetIncludeLifted(), pageSize(req.GetPageSize()))
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListContainmentControlsResponse{}
	for _, c := range rows {
		out.Controls = append(out.Controls, controlOf(c))
	}
	return out, nil
}

// GetRestorationPlan implements ResponseServiceHandler.
func (h *ResponseHandler) GetRestorationPlan(ctx context.Context, req *pantherclawv1.GetRestorationPlanRequest) (*pantherclawv1.GetRestorationPlanResponse, error) {
	id, err := uuid(req.GetPlanId())
	if err != nil {
		return nil, err
	}
	v, err := h.r.GetRestorationPlan(ctx, id)
	if err != nil {
		return nil, err
	}
	p := v.Plan
	out := &pantherclawv1.GetRestorationPlanResponse{
		Id: p.ID.String(), Reason: p.Reason, Staged: p.Staged, State: p.State, RequestedBy: p.RequestedBy, CreateTime: timestamppb.New(p.CreatedAt),
	}
	if p.FinishedAt != nil {
		out.FinishTime = timestamppb.New(*p.FinishedAt)
	}
	var pre struct {
		Checks []rapp.Precondition `json:"checks"`
	}
	if json.Unmarshal(p.Preconditions, &pre) == nil {
		out.Preconditions = preconditionsOf(pre.Checks)
	}
	for _, c := range v.Controls {
		out.Controls = append(out.Controls, controlOf(c))
	}
	for _, st := range v.Stages {
		stage := &pantherclawv1.RestorationStage{Ordinal: st.Ordinal, State: st.State}
		var scope struct {
			Controls []string `json:"controls"`
		}
		if json.Unmarshal(st.Scope, &scope) == nil {
			stage.ControlIds = scope.Controls
		}
		var tests []rapp.TestAction
		if json.Unmarshal(st.Tests, &tests) == nil {
			for _, t := range tests {
				stage.Tests = append(stage.Tests, &pantherclawv1.RestorationTestAction{
					TransactionId: t.Transaction.String(), Evaluation: int32(t.Evaluation), Expect: t.Expect, //nolint:gosec // 1..64
				})
			}
		}
		var results []rapp.TestResult
		if json.Unmarshal(st.Results, &results) == nil {
			stage.Results = resultsOf(results)
		}
		out.Stages = append(out.Stages, stage)
	}
	return out, nil
}

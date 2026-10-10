// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"context"
	"errors"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

type gatewayKey struct{}

// WithGateway returns ctx carrying the authenticated gateway.
func WithGateway(ctx context.Context, gw Gateway) context.Context {
	return context.WithValue(ctx, gatewayKey{}, gw)
}

// GatewayFrom returns the authenticated gateway, if any.
func GatewayFrom(ctx context.Context) (Gateway, bool) {
	gw, ok := ctx.Value(gatewayKey{}).(Gateway)
	return gw, ok && gw.ID != "" && !gw.Org.IsZero()
}

// Handler serves AuthorityService.
type Handler struct {
	pantherclawv1connect.UnimplementedAuthorityServiceHandler
	svc *Service
}

// NewHandler returns the RPC handler for svc.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

func gateway(ctx context.Context) (Gateway, error) {
	gw, ok := GatewayFrom(ctx)
	if !ok {
		return Gateway{}, connect.NewError(connect.CodeUnauthenticated, "gateway credentials required")
	}
	return gw, nil
}

var checklistStatus = map[pipeline.Status]pantherclawv1.ChecklistStatus{
	pipeline.StatusPassed:        pantherclawv1.ChecklistStatus_CHECKLIST_STATUS_PASSED,
	pipeline.StatusFailed:        pantherclawv1.ChecklistStatus_CHECKLIST_STATUS_FAILED,
	pipeline.StatusMissing:       pantherclawv1.ChecklistStatus_CHECKLIST_STATUS_MISSING,
	pipeline.StatusRequired:      pantherclawv1.ChecklistStatus_CHECKLIST_STATUS_REQUIRED,
	pipeline.StatusConstrained:   pantherclawv1.ChecklistStatus_CHECKLIST_STATUS_CONSTRAINED,
	pipeline.StatusAnnotated:     pantherclawv1.ChecklistStatus_CHECKLIST_STATUS_ANNOTATED,
	pipeline.StatusNotEvaluated:  pantherclawv1.ChecklistStatus_CHECKLIST_STATUS_NOT_EVALUATED,
	pipeline.StatusNotApplicable: pantherclawv1.ChecklistStatus_CHECKLIST_STATUS_NOT_APPLICABLE,
}

// modeToProto maps a route mode; an empty mode (an M5 caller) is unspecified.
var modeToProto = map[string]pantherclawv1.DispatchMode{
	pipeline.ModeEnforce: pantherclawv1.DispatchMode_DISPATCH_MODE_ENFORCE, pipeline.ModeMonitor: pantherclawv1.DispatchMode_DISPATCH_MODE_MONITOR,
}

var decisionToProto = map[domain.Decision]pantherclawv1.Decision{
	domain.Allow:                pantherclawv1.Decision_DECISION_ALLOW,
	domain.AllowWithObligations: pantherclawv1.Decision_DECISION_ALLOW_WITH_OBLIGATIONS,
	domain.RequireApproval:      pantherclawv1.Decision_DECISION_REQUIRE_APPROVAL,
	domain.RequireStepUp:        pantherclawv1.Decision_DECISION_REQUIRE_STEP_UP,
	domain.Deny:                 pantherclawv1.Decision_DECISION_DENY,
	domain.CannotAuthorize:      pantherclawv1.Decision_DECISION_CANNOT_AUTHORIZE,
}

// Authorize implements AuthorityServiceHandler.
func (h *Handler) Authorize(ctx context.Context, req *pantherclawv1.AuthorizeRequest) (*pantherclawv1.AuthorizeResponse, error) {
	gw, err := gateway(ctx)
	if err != nil {
		return nil, err
	}
	creds := credentials(req.GetWorkload())
	res, err := h.svc.Authorize(ctx, gw, req.GetActionIr(), creds)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.AuthorizeResponse{
		Decision: decisionToProto[res.Decision], ActionHash: res.ActionHash,
		Permit: res.Permit, Epoch: res.Epoch, Receipt: res.Receipt, Nonce: res.Nonce,
	}
	if !res.TransactionID.IsZero() {
		out.TransactionId = res.TransactionID.String()
	}
	if res.Permit != "" {
		out.PermitId = res.PermitID.String()
	}
	for _, r := range res.Reasons {
		out.Reasons = append(out.Reasons, &pantherclawv1.Reason{Code: r.Code, Check: r.Check, Detail: r.Detail, Decisive: r.Decisive})
	}
	out.DecisionBasisDigest, out.Evaluation, out.Repeat = res.BasisDigest, int32(res.Evaluation), res.Repeat //nolint:gosec // at most 32
	out.Mode, out.AccessMode = modeToProto[res.Mode], res.AccessMode
	out.Wait = WaitInfo(res.Wait)
	if res.EffectiveHash != "" && res.EffectiveHash != res.ActionHash {
		out.EffectiveActionHash = res.EffectiveHash
	}
	for _, it := range res.Checklist {
		out.Checklist = append(out.Checklist, &pantherclawv1.ChecklistItem{
			Step: int32(it.Step), Check: it.Check, Status: checklistStatus[it.Status], Code: it.Code, Detail: it.Detail, //nolint:gosec // 1..10
			Level: it.Level, Decisive: it.Decisive,
		})
	}
	for _, o := range res.Obligations {
		out.Obligations = append(out.Obligations, &pantherclawv1.Obligation{
			Rule: o.Rule, Kind: string(o.Kind), Param: o.Param, Max: o.Max, Values: o.Values, Clamp: o.Clamp, Timing: o.Timing,
		})
	}
	return out, nil
}

// BeginDispatch implements AuthorityServiceHandler.
func (h *Handler) BeginDispatch(ctx context.Context, req *pantherclawv1.BeginDispatchRequest) (*pantherclawv1.BeginDispatchResponse, error) {
	gw, err := gateway(ctx)
	if err != nil {
		return nil, err
	}
	id, err := ids.ParseUUID(req.GetPermitId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, "invalid permit id")
	}
	token, err := h.svc.BeginDispatch(ctx, gw, id, req.GetEpoch(), Outbound{
		Method: req.GetOutboundMethod(), URL: req.GetOutboundUrl(), BodySHA256: req.GetOutboundBodySha256(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.BeginDispatchResponse{ActionToken: token}, nil
}

var outcomeFromProto = map[pantherclawv1.Outcome]Outcome{
	pantherclawv1.Outcome_OUTCOME_ACCEPTED:  Accepted,
	pantherclawv1.Outcome_OUTCOME_FAILED:    Failed,
	pantherclawv1.Outcome_OUTCOME_UNKNOWN:   Unknown,
	pantherclawv1.Outcome_OUTCOME_DELEGATED: Delegated,
}

// RecordExecution implements AuthorityServiceHandler.
func (h *Handler) RecordExecution(ctx context.Context, req *pantherclawv1.RecordExecutionRequest) (*pantherclawv1.RecordExecutionResponse, error) {
	gw, err := gateway(ctx)
	if err != nil {
		return nil, err
	}
	id, err := ids.ParseUUID(req.GetPermitId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, "invalid permit id")
	}
	outcome, ok := outcomeFromProto[req.GetOutcome()]
	if !ok {
		return nil, connect.NewError(connect.CodeInvalidArgument, "invalid outcome")
	}
	receipt, err := h.svc.RecordExecution(ctx, gw, Execution{
		Permit: id, Outcome: outcome, TargetStatus: req.GetTargetStatus(),
		ResponseDigest: req.GetResponseDigest(), DispatchMS: req.GetDispatchMs(), TargetRef: req.GetTargetRef(),
	})
	if err != nil {
		return nil, err
	}
	h.svc.recordCaptures(ctx, gw, id, outcome, req.GetCaptures())
	return &pantherclawv1.RecordExecutionResponse{Receipt: receipt}, nil
}

// GetNonce implements AuthorityServiceHandler.
func (h *Handler) GetNonce(ctx context.Context, _ *pantherclawv1.GetNonceRequest) (*pantherclawv1.GetNonceResponse, error) {
	gw, err := gateway(ctx)
	if err != nil {
		return nil, err
	}
	n, exp, err := h.svc.Nonce(ctx, gw)
	if err != nil {
		return nil, err
	}
	if n == "" {
		return nil, connect.NewError(connect.CodeUnavailable, "workload identity is not configured")
	}
	return &pantherclawv1.GetNonceResponse{Nonce: n, ExpireTime: timestamppb.New(exp)}, nil
}

// credentials maps forwarded workload credentials; nil when absent.
func credentials(w *pantherclawv1.WorkloadCredentials) *Credentials {
	if w == nil {
		return nil
	}
	c := &Credentials{
		Token: w.GetWorkloadToken(), Proof: w.GetProof(), Method: w.GetHtm(), URL: w.GetHtu(), ClientAddress: w.GetClientAddress(),
	}
	copy(c.BodySHA256[:], w.GetBodySha256())
	return c
}

// VerifyWorkload implements AuthorityServiceHandler: a workload that does
// not verify is an answer, not an error, so the gateway can refuse it with
// its PAP-Error code and a fresh nonce.
func (h *Handler) VerifyWorkload(ctx context.Context, req *pantherclawv1.VerifyWorkloadRequest) (*pantherclawv1.VerifyWorkloadResponse, error) {
	gw, err := gateway(ctx)
	if err != nil {
		return nil, err
	}
	var run ids.UUID
	if r := req.GetRunId(); r != "" {
		if run, err = ids.ParseUUID(r); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, "run_id must be a UUID")
		}
	}
	out := &pantherclawv1.VerifyWorkloadResponse{}
	v, err := h.svc.Verify(ctx, gw, credentials(req.GetWorkload()), run)
	var pe *pap.Error
	switch {
	case errors.As(err, &pe):
		out.ErrorCode = string(pe.Code)
	case errors.Is(err, ErrAgentUnusable):
		out.ErrorCode = "agent_unusable"
	case err != nil:
		return nil, err
	default:
		out.Verified, out.InstanceId, out.EnvironmentId, out.Jkt = true, v.Instance.String(), v.Environment.String(), v.JKT
		if !v.RunExpires.IsZero() {
			out.RunExpiresAt = timestamppb.New(v.RunExpires)
		}
	}
	out.Nonce = h.svc.nonce(ctx, gw)
	return out, nil
}

// ReportUnknownWorkload implements AuthorityServiceHandler. A report whose
// proof does not verify is refused with its PAP-Error code.
func (h *Handler) ReportUnknownWorkload(ctx context.Context, req *pantherclawv1.ReportUnknownWorkloadRequest) (*pantherclawv1.ReportUnknownWorkloadResponse, error) {
	gw, err := gateway(ctx)
	if err != nil {
		return nil, err
	}
	c := credentials(req.GetWorkload())
	if c == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, "workload credentials are required")
	}
	id, err := h.svc.ReportUnknown(ctx, gw, UnknownWorkload{Credentials: *c, Route: req.GetRoute(), UserAgent: req.GetUserAgent()})
	if code := pap.CodeOf(err); err != nil && errors.As(err, new(*pap.Error)) {
		return nil, connect.NewError(connect.CodeUnauthenticated, "PAP/1: "+string(code))
	} else if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ReportUnknownWorkloadResponse{Nonce: h.svc.nonce(ctx, gw)}
	if !id.IsZero() {
		out.DiscoveryId = id.String()
	}
	return out, nil
}

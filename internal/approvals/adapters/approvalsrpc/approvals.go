// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package approvalsrpc serves ApprovalService over Connect (G0 M5 part 2):
// reading approval requests and the responses that grant nothing.
// Approving and stepping up are approval-page actions, never RPCs
// (decision 1). A request the caller may not see is NotFound (T-037).
package approvalsrpc

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/approvals/app"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Approvals serves ApprovalService.
type Approvals struct {
	pantherclawv1connect.UnimplementedApprovalServiceHandler
	svc *app.Service
}

// NewApprovals returns the ApprovalService handler.
func NewApprovals(svc *app.Service) *Approvals { return &Approvals{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func parseID(s string) (ids.UUID, error) {
	u, err := ids.ParseUUID(s)
	if err != nil || u.Version() != 7 {
		return ids.UUID{}, errInvalidID
	}
	return u, nil
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}
	return timestamppb.New(*t)
}

func str(u *ids.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

// code strips an enum's prefix ("DECLINE_REASON_TOO_RISKY" → "TOO_RISKY").
func code(name, prefix string) string {
	if strings.HasSuffix(name, "_UNSPECIFIED") {
		return ""
	}
	return strings.TrimPrefix(name, prefix)
}

func stateProto(s string) pantherclawv1.ApprovalState {
	return pantherclawv1.ApprovalState(pantherclawv1.ApprovalState_value["APPROVAL_STATE_"+s])
}

// RequestProto maps a request; satisfied counts the responses that count
// toward each requirement (nil: none known).
func RequestProto(r app.Request, satisfied map[int]int) *pantherclawv1.ApprovalRequest {
	out := &pantherclawv1.ApprovalRequest{
		Id: r.ID.String(), SubjectKind: pantherclawv1.ApprovalSubjectKind(pantherclawv1.ApprovalSubjectKind_value["APPROVAL_SUBJECT_KIND_"+r.SubjectKind]),
		State: stateProto(r.State), AgentId: r.AgentID.String(), RunId: str(r.RunID), TransactionId: str(r.TransactionID),
		GrantId: str(r.GrantID), Operation: r.Operation, Binding: base64.RawURLEncoding.EncodeToString(r.Binding),
		CreateTime: timestamppb.New(r.CreatedAt), DeadlineTime: timestamppb.New(r.DeadlineAt),
		EvidenceDeadlineTime: ts(r.EvidenceDeadlineAt), ApproveTime: ts(r.ApprovedAt), ConsumeByTime: ts(r.ConsumeBy),
		ConsumeTime: ts(r.ConsumedAt), PreviousId: str(r.PreviousID), RequestedBy: str(r.RequestedBy),
	}
	if r.EndReason != nil {
		out.EndReason = *r.EndReason
	}
	if r.GrantRevision != nil {
		out.GrantRevision = *r.GrantRevision
	}
	var reqs []apdomain.Requirement
	if json.Unmarshal(r.Requirements, &reqs) == nil {
		for i, q := range reqs {
			p := &pantherclawv1.ApprovalRequirement{
				Kind: q.Kind, Role: q.Role, Count: int32(q.Count), Independent: q.Independent, Subject: q.Subject, //nolint:gosec // ≤ 5
				Method: q.Method, Satisfied: int32(satisfied[i]), //nolint:gosec // small
			}
			for _, s := range q.Sources {
				p.Sources = append(p.Sources, s.Level+": "+s.Reason)
			}
			out.Requirements = append(out.Requirements, p)
		}
	}
	return out
}

// ListApprovalRequests implements ApprovalServiceHandler.
func (s *Approvals) ListApprovalRequests(ctx context.Context, req *pantherclawv1.ListApprovalRequestsRequest) (*pantherclawv1.ListApprovalRequestsResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	f := app.ListFilter{WaitingForMe: req.GetWaitingForMe()}
	for _, st := range req.GetStates() {
		f.States = append(f.States, apdomain.State(code(st.String(), "APPROVAL_STATE_")))
	}
	if req.AgentId != nil {
		if f.Agent, err = parseID(req.GetAgentId()); err != nil {
			return nil, err
		}
	}
	if req.RunId != nil {
		if f.Run, err = parseID(req.GetRunId()); err != nil {
			return nil, err
		}
	}
	p, err := s.svc.List(ctx, pr, f)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListApprovalRequestsResponse{NextPageToken: p.Next}
	for _, r := range p.Items {
		out.Requests = append(out.Requests, RequestProto(r, nil))
	}
	for _, b := range p.Scopes {
		out.CheckedScopes = append(out.CheckedScopes, scope(b))
	}
	return out, nil
}

// scope names a binding: "approver@TEAM:<id>", or "approver@ORG".
func scope(b td.Binding) string {
	s := string(b.Role) + "@" + string(b.Scope.Type)
	if b.Scope.Type != td.ScopeOrg {
		s += ":" + b.Scope.ID.String()
	}
	return s
}

// GetApprovalRequest implements ApprovalServiceHandler.
func (s *Approvals) GetApprovalRequest(ctx context.Context, req *pantherclawv1.GetApprovalRequestRequest) (*pantherclawv1.GetApprovalRequestResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	v, err := s.svc.View(ctx, id)
	if err != nil {
		return nil, err
	}
	// The stored display, in its canonical form: exactly what the binding's
	// display_hash covers (HR-034).
	display, err := v.Display.Canonical()
	if err != nil || string(display.Hash[:]) != string(v.Request.DisplayHash) {
		return nil, errors.Join(err, errors.New("approvals: the stored display does not match its hash"))
	}
	satisfied := map[int]int{}
	for _, r := range v.Responses {
		if r.Requirement >= 0 && r.Voided == "" {
			satisfied[r.Requirement]++
		}
	}
	r := RequestProto(v.Request, satisfied)
	r.State = stateProto(string(v.State))
	out := &pantherclawv1.GetApprovalRequestResponse{
		Request: r, Display: display.Input, DisplayHash: display.String(),
		Eligibility: &pantherclawv1.ApprovalEligibility{
			CanApprove: v.Eligibility.CanApprove, CanRespond: v.Eligibility.CanRespond, Reason: v.Eligibility.Reason,
		},
	}
	for _, i := range v.Eligibility.Requirements {
		out.Eligibility.Requirements = append(out.Eligibility.Requirements, int32(i)) //nolint:gosec // < 16
	}
	for _, e := range v.Evidence {
		out.Evidence = append(out.Evidence, evidenceProto(e))
	}
	// A decider's note is for people only (design decision 18).
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	for _, x := range v.Responses {
		r := responseProto(x)
		if !c.Human() {
			r.Note = ""
		}
		out.Responses = append(out.Responses, r)
	}
	for _, x := range v.Variants {
		out.Variants = append(out.Variants, &pantherclawv1.ApprovalVariant{
			RequestId: x.Request.String(), State: stateProto(x.State), CreateTime: timestamppb.New(x.CreatedAt),
		})
	}
	return out, nil
}

func evidenceProto(e app.EvidenceLine) *pantherclawv1.ApprovalEvidence {
	kind, id, _ := strings.Cut(e.Author, ":")
	if kind == "instance" {
		kind = "workload"
	}
	return &pantherclawv1.ApprovalEvidence{
		Id: e.ID.String(), AuthorKind: kind, AuthorId: id, Note: e.Note.Text, MixedScript: e.Note.MixedScript, CreateTime: timestamppb.New(e.At),
	}
}

func responseProto(r app.ResponseLine) *pantherclawv1.DeciderResponse {
	out := &pantherclawv1.DeciderResponse{
		Id: r.ID.String(), Kind: pantherclawv1.DeciderResponseKind(pantherclawv1.DeciderResponseKind_value["DECIDER_RESPONSE_KIND_"+r.Kind]),
		UserId: r.User.String(), Requirement: int32(r.Requirement), Note: r.Note.Text, CreateTime: timestamppb.New(r.At), //nolint:gosec // < 16
		VoidReason: r.Voided, VoidTime: ts(r.VoidedAt), CredentialId: str(r.Credential), BatchId: str(r.Batch),
	}
	switch r.Kind {
	case "DECLINE":
		out.DeclineReason = pantherclawv1.DeclineReason(pantherclawv1.DeclineReason_value["DECLINE_REASON_"+r.Reason])
		out.Alternative = pantherclawv1.SaferAlternative(pantherclawv1.SaferAlternative_value["SAFER_ALTERNATIVE_"+r.Alternative])
	case "REQUEST_EVIDENCE":
		out.Question = pantherclawv1.EvidenceQuestion(pantherclawv1.EvidenceQuestion_value["EVIDENCE_QUESTION_"+r.Reason])
	case "PROPOSE_NARROWER":
		out.ProposedParams = []byte(r.Proposed)
	}
	return out
}

// DeclineApprovalRequest implements ApprovalServiceHandler.
func (s *Approvals) DeclineApprovalRequest(ctx context.Context, req *pantherclawv1.DeclineApprovalRequestRequest) (*pantherclawv1.DeclineApprovalRequestResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := s.svc.Decline(ctx, id, code(req.GetReason().String(), "DECLINE_REASON_"),
		code(req.GetAlternative().String(), "SAFER_ALTERNATIVE_"), req.GetNote())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DeclineApprovalRequestResponse{Request: RequestProto(r, nil)}, nil
}

// RequestApprovalEvidence implements ApprovalServiceHandler.
func (s *Approvals) RequestApprovalEvidence(ctx context.Context, req *pantherclawv1.RequestApprovalEvidenceRequest) (*pantherclawv1.RequestApprovalEvidenceResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := s.svc.RequestEvidence(ctx, id, code(req.GetQuestion().String(), "EVIDENCE_QUESTION_"), req.GetNote(),
		req.GetEvidenceDeadlineTime().AsTime())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RequestApprovalEvidenceResponse{Request: RequestProto(r, nil)}, nil
}

// ProposeNarrowerAction implements ApprovalServiceHandler.
func (s *Approvals) ProposeNarrowerAction(ctx context.Context, req *pantherclawv1.ProposeNarrowerActionRequest) (*pantherclawv1.ProposeNarrowerActionResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	p, err := s.svc.ProposeNarrower(ctx, id, req.GetParams(), req.GetNote(), req.GetValidateOnly())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ProposeNarrowerActionResponse{
		Request: RequestProto(p.Request, nil), Params: p.Simulation.Params,
		SimulatedDecision: pantherclawv1.Decision(pantherclawv1.Decision_value["DECISION_"+p.Simulation.Decision]),
	}
	for _, r := range p.Simulation.Reasons {
		out.SimulatedReasons = append(out.SimulatedReasons, &pantherclawv1.Reason{Code: r.Code, Check: r.Check, Detail: r.Detail, Decisive: r.Decisive})
	}
	return out, nil
}

// SubmitApprovalEvidence implements ApprovalServiceHandler.
func (s *Approvals) SubmitApprovalEvidence(ctx context.Context, req *pantherclawv1.SubmitApprovalEvidenceRequest) (*pantherclawv1.SubmitApprovalEvidenceResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	r, evidence, err := s.svc.SubmitEvidence(ctx, id, req.GetNote())
	if err != nil {
		return nil, err
	}
	note := apdomain.Clean("evidence", req.GetNote(), apdomain.MaxUntrustedRunes)
	return &pantherclawv1.SubmitApprovalEvidenceResponse{
		Evidence: &pantherclawv1.ApprovalEvidence{
			Id: evidence.String(), AuthorKind: "user", Note: note.Text, MixedScript: note.MixedScript, CreateTime: timestamppb.Now(),
		},
		Request: RequestProto(r, nil),
	}, nil
}

// DeclineApprovalBatch implements ApprovalServiceHandler: up to 25 waiting
// requests for one operation, each with its own response and audit event
// (HR-175, Team edition).
func (s *Approvals) DeclineApprovalBatch(ctx context.Context, req *pantherclawv1.DeclineApprovalBatchRequest) (*pantherclawv1.DeclineApprovalBatchResponse, error) {
	var list []ids.UUID
	for _, x := range req.GetIds() {
		id, err := parseID(x)
		if err != nil {
			return nil, err
		}
		list = append(list, id)
	}
	batch, rows, err := s.svc.DeclineBatch(ctx, list, code(req.GetReason().String(), "DECLINE_REASON_"), req.GetNote())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.DeclineApprovalBatchResponse{BatchId: batch.String()}
	for _, r := range rows {
		out.Requests = append(out.Requests, RequestProto(r, nil))
	}
	return out, nil
}

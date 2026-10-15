// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package posturerpc serves PostureService over Connect (G0 M10 D30).
// Handlers only translate: authentication, the coarse permission check and
// protovalidate have run before a handler is called, and the use cases
// check posture.read or posture.manage per finding and the edition.
package posturerpc

import (
	"context"
	"encoding/json/v2"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/posture/app"
	"github.com/katocxl/pantherclaw/internal/posture/domain"
)

// Handler serves PostureService.
type Handler struct {
	pantherclawv1connect.UnimplementedPostureServiceHandler
	svc *app.Service
}

// New returns the PostureService handler.
func New(svc *app.Service) *Handler { return &Handler{svc: svc} }

var states = map[domain.State]pb.PostureState{
	domain.Open: pb.PostureState_POSTURE_STATE_OPEN, domain.Assigned: pb.PostureState_POSTURE_STATE_ASSIGNED,
	domain.Testing: pb.PostureState_POSTURE_STATE_TESTING, domain.Remediated: pb.PostureState_POSTURE_STATE_REMEDIATED,
	domain.AcceptedTemporarily: pb.PostureState_POSTURE_STATE_ACCEPTED_TEMPORARILY,
	domain.EvidenceIncomplete:  pb.PostureState_POSTURE_STATE_EVIDENCE_INCOMPLETE,
}

func stateOf(s pb.PostureState) domain.State {
	for k, v := range states {
		if v == s {
			return k
		}
	}
	return ""
}

func str(u *ids.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func id(s string) (ids.UUID, error) {
	u, err := ids.ParseUUID(s)
	if err != nil {
		return u, app.ErrFindingNotFound
	}
	return u, nil
}

func findingPB(f dbq.PcPostureFinding) *pb.PostureFinding {
	detail := map[string]string{}
	_ = json.Unmarshal(f.Detail, &detail) // stored by the reconciler as a flat object
	out := &pb.PostureFinding{
		Id: f.ID.String(), Kind: f.Kind, RootCause: f.RootCause, AgentId: str(f.AgentID), ConnectionId: str(f.ConnectionID),
		GrantId: str(f.GrantID), CoverageFindingId: str(f.CoverageFindingID), Title: f.Title, Detail: detail,
		AffectedPaths: f.AffectedPaths, Severity: f.Severity, State: states[domain.State(f.State)], OwnerUserId: str(f.OwnerUserID),
		LastSnapshotId: f.LastSnapshotID.String(), RemediatedSnapshotId: str(f.RemediatedSnapshotID),
		FirstSeenTime: timestamppb.New(f.FirstSeenAt), LastSeenTime: timestamppb.New(f.LastSeenAt),
		StateChangeTime: timestamppb.New(f.StateChangedAt),
	}
	if f.AcceptedUntil != nil {
		out.AcceptUntil = timestamppb.New(*f.AcceptedUntil)
	}
	if f.AcceptedReason != nil {
		out.AcceptReason = *f.AcceptedReason
	}
	return out
}

// ListPostureFindings implements PostureServiceHandler.
func (h *Handler) ListPostureFindings(ctx context.Context, req *pb.ListPostureFindingsRequest) (*pb.ListPostureFindingsResponse, error) {
	sts := make([]domain.State, 0, len(req.GetStates()))
	for _, s := range req.GetStates() {
		sts = append(sts, stateOf(s))
	}
	rows, next, restricted, err := h.svc.List(ctx, sts, req.GetKind(), req.GetRootCause(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pb.ListPostureFindingsResponse{NextPageToken: next, Restricted: restricted}
	for _, f := range rows {
		out.Findings = append(out.Findings, findingPB(f))
	}
	return out, nil
}

// ListPostureRootCauses implements PostureServiceHandler.
func (h *Handler) ListPostureRootCauses(ctx context.Context, _ *pb.ListPostureRootCausesRequest) (*pb.ListPostureRootCausesResponse, error) {
	rcs, restricted, err := h.svc.RootCauses(ctx)
	if err != nil {
		return nil, err
	}
	out := &pb.ListPostureRootCausesResponse{Restricted: restricted}
	for _, r := range rcs {
		out.RootCauses = append(out.RootCauses, &pb.PostureRootCause{
			RootCause: r.RootCause, Findings: int32(min(r.Findings, 1<<30)), MaxSeverity: r.MaxSeverity, Kinds: r.Kinds, //nolint:gosec // G115: bounded
		})
	}
	return out, nil
}

// GetPostureFinding implements PostureServiceHandler.
func (h *Handler) GetPostureFinding(ctx context.Context, req *pb.GetPostureFindingRequest) (*pb.GetPostureFindingResponse, error) {
	fid, err := id(req.GetId())
	if err != nil {
		return nil, err
	}
	f, err := h.svc.Get(ctx, fid)
	if err != nil {
		return nil, err
	}
	out := &pb.GetPostureFindingResponse{Finding: findingPB(f.Finding)}
	for _, e := range f.Events {
		x := &pb.PostureFindingEvent{
			Kind: e.Kind, ToState: states[domain.State(e.ToState)], Actor: e.Actor, SnapshotId: str(e.SnapshotID),
			Time: timestamppb.New(e.OccurredAt),
		}
		if e.FromState != nil {
			x.FromState = states[domain.State(*e.FromState)]
		}
		if e.Note != nil {
			x.Note = *e.Note
		}
		out.Events = append(out.Events, x)
	}
	return out, nil
}

// AssignPostureFinding implements PostureServiceHandler.
func (h *Handler) AssignPostureFinding(ctx context.Context, req *pb.AssignPostureFindingRequest) (*pb.AssignPostureFindingResponse, error) {
	fid, err := id(req.GetId())
	if err != nil {
		return nil, err
	}
	owner, err := ids.ParseUUID(req.GetOwnerUserId())
	if err != nil {
		return nil, app.ErrOwner
	}
	f, err := h.svc.Assign(ctx, fid, owner)
	if err != nil {
		return nil, err
	}
	return &pb.AssignPostureFindingResponse{Finding: findingPB(f)}, nil
}

// StartPostureTesting implements PostureServiceHandler.
func (h *Handler) StartPostureTesting(ctx context.Context, req *pb.StartPostureTestingRequest) (*pb.StartPostureTestingResponse, error) {
	fid, err := id(req.GetId())
	if err != nil {
		return nil, err
	}
	f, err := h.svc.StartTesting(ctx, fid, req.GetNote())
	if err != nil {
		return nil, err
	}
	return &pb.StartPostureTestingResponse{Finding: findingPB(f)}, nil
}

// AcceptPostureFinding implements PostureServiceHandler.
func (h *Handler) AcceptPostureFinding(ctx context.Context, req *pb.AcceptPostureFindingRequest) (*pb.AcceptPostureFindingResponse, error) {
	fid, err := id(req.GetId())
	if err != nil {
		return nil, err
	}
	f, err := h.svc.Accept(ctx, fid, req.GetUntil().AsTime(), req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pb.AcceptPostureFindingResponse{Finding: findingPB(f)}, nil
}

// MarkPostureEvidenceIncomplete implements PostureServiceHandler.
func (h *Handler) MarkPostureEvidenceIncomplete(ctx context.Context, req *pb.MarkPostureEvidenceIncompleteRequest) (*pb.MarkPostureEvidenceIncompleteResponse, error) {
	fid, err := id(req.GetId())
	if err != nil {
		return nil, err
	}
	f, err := h.svc.MarkIncomplete(ctx, fid, req.GetNote())
	if err != nil {
		return nil, err
	}
	return &pb.MarkPostureEvidenceIncompleteResponse{Finding: findingPB(f)}, nil
}

// ReopenPostureFinding implements PostureServiceHandler.
func (h *Handler) ReopenPostureFinding(ctx context.Context, req *pb.ReopenPostureFindingRequest) (*pb.ReopenPostureFindingResponse, error) {
	fid, err := id(req.GetId())
	if err != nil {
		return nil, err
	}
	f, err := h.svc.Reopen(ctx, fid, req.GetNote())
	if err != nil {
		return nil, err
	}
	return &pb.ReopenPostureFindingResponse{Finding: findingPB(f)}, nil
}

// AddPostureNote implements PostureServiceHandler.
func (h *Handler) AddPostureNote(ctx context.Context, req *pb.AddPostureNoteRequest) (*pb.AddPostureNoteResponse, error) {
	fid, err := id(req.GetId())
	if err != nil {
		return nil, err
	}
	f, err := h.svc.AddNote(ctx, fid, req.GetNote())
	if err != nil {
		return nil, err
	}
	return &pb.AddPostureNoteResponse{Finding: findingPB(f)}, nil
}

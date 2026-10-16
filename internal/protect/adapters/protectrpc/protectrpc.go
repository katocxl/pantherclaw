// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package protectrpc serves ProtectedChangeService and PublisherService
// (G0 M11 part 2 D42, D43; HR-292, HR-293). The step-up actions
// (ApplyEmergencyProtectedChange, MarkCompromised) carry no step-up over
// the API, so the use cases refuse them with STEP_UP_REQUIRED; their pages
// call the same use cases with the session's step-up (D53).
package protectrpc

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
)

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

// Changes serves ProtectedChangeService.
type Changes struct {
	pantherclawv1connect.UnimplementedProtectedChangeServiceHandler
	s *protect.Service
}

// NewChanges returns a handler over s.
func NewChanges(s *protect.Service) *Changes { return &Changes{s: s} }

// GetProtectedChangeSettings implements ProtectedChangeServiceHandler.
func (h *Changes) GetProtectedChangeSettings(ctx context.Context, _ *pb.GetProtectedChangeSettingsRequest) (*pb.GetProtectedChangeSettingsResponse, error) {
	all, err := h.s.GetSettings(ctx)
	if err != nil {
		return nil, err
	}
	out := &pb.GetProtectedChangeSettingsResponse{}
	for _, st := range all {
		out.Settings = append(out.Settings, settingOf(st))
	}
	return out, nil
}

// SetProtectedCategoryMode implements ProtectedChangeServiceHandler.
func (h *Changes) SetProtectedCategoryMode(ctx context.Context, req *pb.SetProtectedCategoryModeRequest) (*pb.SetProtectedCategoryModeResponse, error) {
	st, err := h.s.SetCategoryMode(ctx, protect.Category(req.GetCategory()), protect.Mode(req.GetMode()))
	if err != nil {
		return nil, err
	}
	return &pb.SetProtectedCategoryModeResponse{Setting: settingOf(st)}, nil
}

// ListProtectedChanges implements ProtectedChangeServiceHandler.
func (h *Changes) ListProtectedChanges(ctx context.Context, req *pb.ListProtectedChangesRequest) (*pb.ListProtectedChangesResponse, error) {
	var before ids.UUID
	if t := req.GetPageToken(); t != "" {
		var err error
		if before, err = ids.ParseUUID(t); err != nil {
			return nil, errInvalidID
		}
	}
	size := int(req.GetPageSize())
	if size == 0 {
		size = 50
	}
	rows, err := h.s.List(ctx, req.GetState(), protect.Category(req.GetCategory()), before, size)
	if err != nil {
		return nil, err
	}
	out := &pb.ListProtectedChangesResponse{}
	for _, r := range rows {
		out.Changes = append(out.Changes, ChangeOf(r))
	}
	if len(rows) == size {
		out.NextPageToken = rows[len(rows)-1].ID.String()
	}
	return out, nil
}

// ApplyEmergencyProtectedChange implements ProtectedChangeServiceHandler:
// without a browser session's step-up it is refused (STEP_UP_REQUIRED).
func (h *Changes) ApplyEmergencyProtectedChange(ctx context.Context, req *pb.ApplyEmergencyProtectedChangeRequest) (*pb.ApplyEmergencyProtectedChangeResponse, error) {
	id, err := ids.ParseUUID(req.GetChangeRequestId())
	if err != nil {
		return nil, errInvalidID
	}
	row, err := h.s.ApplyEmergency(ctx, id, stepup.StepUp{})
	if err != nil {
		return nil, err
	}
	return &pb.ApplyEmergencyProtectedChangeResponse{Change: ChangeOf(row)}, nil
}

// Publishers serves PublisherService.
type Publishers struct {
	pantherclawv1connect.UnimplementedPublisherServiceHandler
	p *protect.Publishers
}

// NewPublishers returns a handler over p.
func NewPublishers(p *protect.Publishers) *Publishers { return &Publishers{p: p} }

// MarkCompromised implements PublisherServiceHandler: without a browser
// session's step-up it is refused (STEP_UP_REQUIRED).
func (h *Publishers) MarkCompromised(ctx context.Context, req *pb.MarkCompromisedRequest) (*pb.MarkCompromisedResponse, error) {
	user, err := ids.ParseUUID(req.GetUserId())
	if err != nil {
		return nil, errInvalidID
	}
	row, err := h.p.MarkCompromised(ctx, user, req.GetSince().AsTime(), req.GetReason(), stepup.StepUp{})
	if err != nil {
		return nil, err
	}
	return &pb.MarkCompromisedResponse{Compromise: CompromiseOf(row)}, nil
}

// ListCompromises implements PublisherServiceHandler.
func (h *Publishers) ListCompromises(ctx context.Context, req *pb.ListCompromisesRequest) (*pb.ListCompromisesResponse, error) {
	rows, err := h.p.List(ctx, req.GetActiveOnly(), 200)
	if err != nil {
		return nil, err
	}
	out := &pb.ListCompromisesResponse{}
	for _, r := range rows {
		out.Compromises = append(out.Compromises, CompromiseOf(r))
	}
	return out, nil
}

// ListExposed implements PublisherServiceHandler.
func (h *Publishers) ListExposed(ctx context.Context, req *pb.ListExposedRequest) (*pb.ListExposedResponse, error) {
	id, err := ids.ParseUUID(req.GetCompromiseId())
	if err != nil {
		return nil, errInvalidID
	}
	cp, err := h.p.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pb.ListExposedResponse{Compromise: CompromiseOf(cp.PcCompromisedPublisher)}
	for _, i := range cp.Items {
		out.Items = append(out.Items, ItemOf(i))
	}
	return out, nil
}

// ReviewExposed implements PublisherServiceHandler.
func (h *Publishers) ReviewExposed(ctx context.Context, req *pb.ReviewExposedRequest) (*pb.ReviewExposedResponse, error) {
	id, err := ids.ParseUUID(req.GetCompromiseId())
	if err != nil {
		return nil, errInvalidID
	}
	item, err := h.p.ReviewExposed(ctx, id, req.GetKind(), req.GetItemId(), req.GetDecision(), req.GetNote())
	if err != nil {
		return nil, err
	}
	return &pb.ReviewExposedResponse{Item: ItemOf(item)}, nil
}

// ClearCompromise implements PublisherServiceHandler.
func (h *Publishers) ClearCompromise(ctx context.Context, req *pb.ClearCompromiseRequest) (*pb.ClearCompromiseResponse, error) {
	id, err := ids.ParseUUID(req.GetCompromiseId())
	if err != nil {
		return nil, errInvalidID
	}
	req2, err := h.p.ClearCompromise(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pb.ClearCompromiseResponse{ChangeRequestId: req2.String()}, nil
}

func settingOf(st protect.Setting) *pb.ProtectedCategorySetting {
	out := &pb.ProtectedCategorySetting{Category: string(st.Category), Mode: string(st.Mode)}
	if !st.UpdatedBy.IsZero() {
		out.UpdatedBy, out.UpdateTime = "user:"+st.UpdatedBy.String(), timestamppb.New(st.UpdatedAt)
	}
	return out
}

// ChangeOf converts a stored protected change (also the page's view).
func ChangeOf(r dbq.PcProtectedChange) *pb.ProtectedChange {
	out := &pb.ProtectedChange{
		Id: r.ID.String(), Category: r.Category, Surface: r.Surface, Subject: r.Subject, Widening: r.Widening,
		Digest: hex.EncodeToString(r.Digest), Author: "user:" + r.Author.String(), State: r.State,
		CreateTime: timestamppb.New(r.CreatedAt), ChangeRequestId: str(r.ChangeRequestID), Publisher: user(r.Publisher),
		DecideTime: ts(r.DecidedAt), ReviewRequestId: str(r.ReviewRequestID), ReviewDueTime: ts(r.ReviewDueAt),
		ReviewedBy: user(r.ReviewedBy), ReviewTime: ts(r.ReviewedAt),
	}
	if r.DecidedReason != nil {
		out.DecidedReason = *r.DecidedReason
	}
	var summary map[string]string
	if json.Unmarshal(r.Summary, &summary) == nil {
		out.Summary = summary
	}
	return out
}

// CompromiseOf converts a mark.
func CompromiseOf(r dbq.PcCompromisedPublisher) *pb.PublisherCompromise {
	return &pb.PublisherCompromise{
		Id: r.ID.String(), UserId: r.UserID.String(), Since: timestamppb.New(r.Since), Reason: r.Reason, State: r.State,
		MarkedBy: r.MarkedBy.String(), MarkTime: timestamppb.New(r.MarkedAt), ClearRequestId: str(r.ClearRequestID),
		ClearTime: ts(r.ClearedAt),
	}
}

// ItemOf converts an exposed item.
func ItemOf(i protect.Item) *pb.ExposedItem {
	out := &pb.ExposedItem{Kind: i.Kind, Id: i.ID, Label: i.Label, Time: timestamppb.New(i.At)}
	if r := i.Review; r != nil {
		out.Decision, out.Reviewer = r.Decision, r.Reviewer.String()
		if r.Note != nil {
			out.Note = *r.Note
		}
		if !r.ReviewedAt.IsZero() {
			out.ReviewTime = timestamppb.New(r.ReviewedAt)
		}
	}
	return out
}

func str(u *ids.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func user(u *ids.UUID) string {
	if u == nil {
		return ""
	}
	return "user:" + u.String()
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

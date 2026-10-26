// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/support"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type breakGlassHandler struct {
	pantherclawv1connect.UnimplementedBreakGlassServiceHandler
	s *support.Service
}

func holderProto(h support.Holder) *pantherclawv1.BreakGlassHolder {
	return &pantherclawv1.BreakGlassHolder{UserId: h.User.String(), Role: string(h.Role), DesignatedBy: h.DesignatedBy.String(), DesignatedAt: timestamppb.New(h.DesignatedAt)}
}

func activationProto(a support.Activation) *pantherclawv1.BreakGlassActivation {
	out := &pantherclawv1.BreakGlassActivation{Id: a.ID.String(), UserId: a.User.String(), Role: string(a.Role), Reason: a.Reason,
		StartedAt: timestamppb.New(a.StartedAt), ExpiresAt: timestamppb.New(a.ExpiresAt), Active: a.Active, EndedBy: a.EndedBy}
	if a.EndedAt != nil {
		out.EndedAt = timestamppb.New(*a.EndedAt)
	}
	return out
}

func (h breakGlassHandler) ListBreakGlassHolders(ctx context.Context, _ *pantherclawv1.ListBreakGlassHoldersRequest) (*pantherclawv1.ListBreakGlassHoldersResponse, error) {
	rows, err := h.s.ListHolders(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListBreakGlassHoldersResponse{}
	for _, r := range rows {
		out.Holders = append(out.Holders, holderProto(r))
	}
	return out, nil
}

func (h breakGlassHandler) SetBreakGlassHolders(ctx context.Context, req *pantherclawv1.SetBreakGlassHoldersRequest) (*pantherclawv1.SetBreakGlassHoldersResponse, error) {
	var in []support.Designation
	for _, r := range req.GetHolders() {
		id, err := ids.ParseUUID(r.GetUserId())
		if err != nil {
			return nil, support.ErrDesignation
		}
		in = append(in, support.Designation{User: id, Role: td.RoleName(r.GetRole())})
	}
	rows, err := h.s.SetHolders(ctx, in)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.SetBreakGlassHoldersResponse{}
	for _, r := range rows {
		out.Holders = append(out.Holders, holderProto(r))
	}
	return out, nil
}

// ActivateBreakGlass is deliberately page-only (D38). A caller may never
// supply a step-up or reason through a plain Connect call.
func (h breakGlassHandler) ActivateBreakGlass(ctx context.Context, req *pantherclawv1.ActivateBreakGlassRequest) (*pantherclawv1.ActivateBreakGlassResponse, error) {
	_, err := h.s.ActivateBreakGlass(ctx, req.GetReason(), int(req.GetDurationMinutes()), nil)
	return nil, err
}

func (h breakGlassHandler) EndBreakGlass(ctx context.Context, req *pantherclawv1.EndBreakGlassRequest) (*pantherclawv1.EndBreakGlassResponse, error) {
	id, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, support.ErrActivationNotFound
	}
	a, err := h.s.EndBreakGlass(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.EndBreakGlassResponse{Activation: activationProto(a)}, nil
}

func (h breakGlassHandler) GetMyBreakGlass(ctx context.Context, _ *pantherclawv1.GetMyBreakGlassRequest) (*pantherclawv1.GetMyBreakGlassResponse, error) {
	holder, a, err := h.s.MyBreakGlass(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetMyBreakGlassResponse{}
	if holder != nil {
		out.Holder, out.Role = true, string(holder.Role)
	}
	if a != nil {
		out.Active = activationProto(*a)
	}
	return out, nil
}

func (h breakGlassHandler) ListBreakGlassActivations(ctx context.Context, req *pantherclawv1.ListBreakGlassActivationsRequest) (*pantherclawv1.ListBreakGlassActivationsResponse, error) {
	p, err := h.s.ListActivations(ctx, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListBreakGlassActivationsResponse{NextPageToken: p.Next}
	for _, a := range p.Items {
		out.Activations = append(out.Activations, activationProto(a))
	}
	return out, nil
}

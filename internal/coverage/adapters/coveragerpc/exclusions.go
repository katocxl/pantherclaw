// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package coveragerpc

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// CreateExclusion implements CoverageServiceHandler.
func (h *Handler) CreateExclusion(ctx context.Context, req *pantherclawv1.CreateExclusionRequest) (*pantherclawv1.CreateExclusionResponse, error) {
	conn, err := idOf(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	agent, err := optID(req.AgentId)
	if err != nil {
		return nil, err
	}
	r := app.ExclusionRequest{
		Connection: conn, Agent: agent, Operation: req.Operation, Reason: req.GetReason(),
		ExpiresInDays: int(req.GetExpiresInDays()),
	}
	for k, v := range kinds {
		if v == req.GetRouteKind() && req.GetRouteKind() != pantherclawv1.CoverageRouteKind_COVERAGE_ROUTE_KIND_UNSPECIFIED {
			r.Kind = k
		}
	}
	if r.Kind == domain.KindChannel {
		return nil, app.ErrExclusion
	}
	x, err := h.svc.CreateExclusion(ctx, r)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateExclusionResponse{Exclusion: exclusionProto(x)}, nil
}

// RevokeExclusion implements CoverageServiceHandler.
func (h *Handler) RevokeExclusion(ctx context.Context, req *pantherclawv1.RevokeExclusionRequest) (*pantherclawv1.RevokeExclusionResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	x, err := h.svc.RevokeExclusion(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeExclusionResponse{Exclusion: exclusionProto(x)}, nil
}

// ListExclusions implements CoverageServiceHandler.
func (h *Handler) ListExclusions(ctx context.Context, req *pantherclawv1.ListExclusionsRequest) (*pantherclawv1.ListExclusionsResponse, error) {
	conn, err := optID(req.ConnectionId)
	if err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListExclusions(ctx, conn, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListExclusionsResponse{NextPageToken: next}
	for _, x := range rows {
		p := exclusionProto(x.PcCoverageExclusion)
		p.State = x.EffectiveState
		out.Exclusions = append(out.Exclusions, p)
	}
	return out, nil
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pointsrpc serves EnforcementPointService over Connect (G0 M14
// D29). Activation needs a step-up, so it passes none here: the use case
// answers STEP_UP_REQUIRED and the confirm page makes it.
package pointsrpc

import (
	"context"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/enforcementpoints"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Handler serves EnforcementPointService.
type Handler struct {
	pantherclawv1connect.UnimplementedEnforcementPointServiceHandler
	s         *enforcementpoints.Service
	publicURL string
}

// New returns the handler; publicURL builds the confirm page links.
func New(s *enforcementpoints.Service, publicURL string) *Handler {
	return &Handler{s: s, publicURL: strings.TrimRight(publicURL, "/")}
}

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil || id.IsZero() {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

func idsOf(ss []string) ([]ids.UUID, error) {
	out := make([]ids.UUID, len(ss))
	for i, s := range ss {
		id, err := idOf(s)
		if err != nil {
			return nil, err
		}
		out[i] = id
	}
	return out, nil
}

func strs(us []ids.UUID) []string {
	out := make([]string, len(us))
	for i, u := range us {
		out[i] = u.String()
	}
	return out
}

func tsp(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}
	return timestamppb.New(*t)
}

// Proto is a point as the API shows it; confirmURL is its confirm page.
func Proto(p enforcementpoints.Point, confirmURL string) *pantherclawv1.EnforcementPoint {
	out := &pantherclawv1.EnforcementPoint{
		Id: p.ID.String(), Name: p.Name, Description: p.Description, ServiceAccountId: p.ServiceAccount.String(),
		ConnectionIds: strs(p.Connections), ProposedConnectionIds: strs(p.Proposed), RatePerSecond: int32(p.RatePerSecond), //nolint:gosec // 1..1000
		State: p.State, CreatedBy: p.CreatedBy.String(), CreateTime: timestamppb.New(p.CreatedAt),
		ActivateTime: tsp(p.ActivatedAt), DisableTime: tsp(p.DisabledAt), ConfirmUrl: confirmURL,
	}
	if p.ActivatedBy != nil {
		out.ActivatedBy = p.ActivatedBy.String()
	}
	return out
}

// ConfirmURL is a point's confirm page.
func ConfirmURL(publicURL string, org ids.OrgID, id ids.UUID) string {
	return strings.TrimRight(publicURL, "/") + enforcementpoints.PagePath + id.String() + "/confirm?org=" + org.String()
}

func (h *Handler) proto(ctx context.Context, p enforcementpoints.Point) *pantherclawv1.EnforcementPoint {
	var confirm string
	if c, err := tenancy.CallerFrom(ctx); err == nil && p.State != enforcementpoints.StateDisabled {
		confirm = ConfirmURL(h.publicURL, c.Org, p.ID)
	}
	return Proto(p, confirm)
}

// CreateEnforcementPoint implements EnforcementPointServiceHandler.
func (h *Handler) CreateEnforcementPoint(ctx context.Context, req *pantherclawv1.CreateEnforcementPointRequest) (
	*pantherclawv1.CreateEnforcementPointResponse, error,
) {
	sa, err := idOf(req.GetServiceAccountId())
	if err != nil {
		return nil, err
	}
	conns, err := idsOf(req.GetConnectionIds())
	if err != nil {
		return nil, err
	}
	p, err := h.s.Create(ctx, enforcementpoints.NewPoint{
		Name: req.GetName(), Description: req.GetDescription(), ServiceAccount: sa, Connections: conns,
		RatePerSecond: int(req.GetRatePerSecond()),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateEnforcementPointResponse{Point: h.proto(ctx, p)}, nil
}

// ActivateEnforcementPoint implements EnforcementPointServiceHandler:
// always STEP_UP_REQUIRED over the API (D29).
func (h *Handler) ActivateEnforcementPoint(ctx context.Context, req *pantherclawv1.ActivateEnforcementPointRequest) (
	*pantherclawv1.ActivateEnforcementPointResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	p, err := h.s.Activate(ctx, id, nil)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ActivateEnforcementPointResponse{Point: h.proto(ctx, p)}, nil
}

// UpdateEnforcementPointConnections implements
// EnforcementPointServiceHandler.
func (h *Handler) UpdateEnforcementPointConnections(ctx context.Context, req *pantherclawv1.UpdateEnforcementPointConnectionsRequest) (
	*pantherclawv1.UpdateEnforcementPointConnectionsResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	conns, err := idsOf(req.GetConnectionIds())
	if err != nil {
		return nil, err
	}
	p, pending, err := h.s.UpdateConnections(ctx, id, conns)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.UpdateEnforcementPointConnectionsResponse{Point: h.proto(ctx, p), ConfirmationRequired: pending}, nil
}

// DisableEnforcementPoint implements EnforcementPointServiceHandler.
func (h *Handler) DisableEnforcementPoint(ctx context.Context, req *pantherclawv1.DisableEnforcementPointRequest) (
	*pantherclawv1.DisableEnforcementPointResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	p, err := h.s.Disable(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DisableEnforcementPointResponse{Point: h.proto(ctx, p)}, nil
}

// GetEnforcementPoint implements EnforcementPointServiceHandler.
func (h *Handler) GetEnforcementPoint(ctx context.Context, req *pantherclawv1.GetEnforcementPointRequest) (
	*pantherclawv1.GetEnforcementPointResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	p, err := h.s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetEnforcementPointResponse{Point: h.proto(ctx, p)}, nil
}

// ListEnforcementPoints implements EnforcementPointServiceHandler.
func (h *Handler) ListEnforcementPoints(ctx context.Context, _ *pantherclawv1.ListEnforcementPointsRequest) (
	*pantherclawv1.ListEnforcementPointsResponse, error,
) {
	ps, err := h.s.List(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListEnforcementPointsResponse{}
	for _, p := range ps {
		out.Points = append(out.Points, h.proto(ctx, p))
	}
	return out, nil
}

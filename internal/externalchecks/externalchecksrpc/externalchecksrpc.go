// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package externalchecksrpc serves ExternalCheckService over Connect (G0
// M16 D81; HR-436..440).
package externalchecksrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/externalchecks"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler serves ExternalCheckService.
type Handler struct {
	pantherclawv1connect.UnimplementedExternalCheckServiceHandler
	svc *externalchecks.Service
}

// New returns the ExternalCheckService handler.
func New(svc *externalchecks.Service) *Handler { return &Handler{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

// CreateExternalCheck implements ExternalCheckServiceHandler.
func (h *Handler) CreateExternalCheck(ctx context.Context, req *pantherclawv1.CreateExternalCheckRequest) (
	*pantherclawv1.CreateExternalCheckResponse, error,
) {
	c, err := h.svc.Create(ctx, externalchecks.NewCheck{
		Name: req.GetName(), Endpoint: req.GetEndpoint(), CAPEM: req.GetCaPem(), TimeoutMs: int(req.GetTimeoutMs()),
		Operations: req.GetOperations(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateExternalCheckResponse{Check: h.proto(c)}, nil
}

// ActivateExternalCheck implements ExternalCheckServiceHandler: always
// STEP_UP_REQUIRED over the API (HR-438); a person activates a check on
// its page.
func (h *Handler) ActivateExternalCheck(ctx context.Context, req *pantherclawv1.ActivateExternalCheckRequest) (
	*pantherclawv1.ActivateExternalCheckResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	c, err := h.svc.Activate(ctx, id, nil)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ActivateExternalCheckResponse{Check: h.proto(c)}, nil
}

// DisableExternalCheck implements ExternalCheckServiceHandler.
func (h *Handler) DisableExternalCheck(ctx context.Context, req *pantherclawv1.DisableExternalCheckRequest) (
	*pantherclawv1.DisableExternalCheckResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	c, err := h.svc.Disable(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DisableExternalCheckResponse{Check: h.proto(c)}, nil
}

// ListExternalChecks implements ExternalCheckServiceHandler.
func (h *Handler) ListExternalChecks(ctx context.Context, req *pantherclawv1.ListExternalChecksRequest) (
	*pantherclawv1.ListExternalChecksResponse, error,
) {
	rows, err := h.svc.List(ctx, req.GetIncludeDisabled())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListExternalChecksResponse{}
	for _, c := range rows {
		out.Checks = append(out.Checks, h.proto(c))
	}
	return out, nil
}

// TestExternalCheck implements ExternalCheckServiceHandler.
func (h *Handler) TestExternalCheck(ctx context.Context, req *pantherclawv1.TestExternalCheckRequest) (
	*pantherclawv1.TestExternalCheckResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	ans, input, err := h.svc.Test(ctx, id, req.GetOperation())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.TestExternalCheckResponse{
		Decision: ans.Decision, Reasons: ans.Reasons, ErrorCode: ans.Unavailable,
		LatencyMs: int32(ans.Latency / time.Millisecond), Input: input, //nolint:gosec // G115: bounded by the 1 s timeout
	}, nil
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func (h *Handler) proto(c externalchecks.Check) *pantherclawv1.ExternalCheck {
	out := &pantherclawv1.ExternalCheck{
		Id: c.ID.String(), Name: c.Name, Endpoint: c.Endpoint, CustomCa: c.CAPEM != "",
		TimeoutMs: int32(c.TimeoutMs), Operations: c.Operations, State: c.State, CreatedBy: c.CreatedBy, //nolint:gosec // G115: ≤ 1000
		CreateTime: timestamppb.New(c.CreatedAt), ActivateTime: ts(c.ActivatedAt), UpdateTime: timestamppb.New(c.UpdatedAt),
		ConfirmUrl: h.svc.ConfirmURL(c.ID),
	}
	if c.ActivatedBy != nil {
		out.ActivatedBy = c.ActivatedBy.String()
	}
	return out
}

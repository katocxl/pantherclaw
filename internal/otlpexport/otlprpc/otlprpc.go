// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package otlprpc serves OTLPDestinationService over Connect (G0 M36
// D1061; HR-786).
package otlprpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/otlpexport"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler serves OTLPDestinationService.
type Handler struct {
	pantherclawv1connect.UnimplementedOTLPDestinationServiceHandler
	svc *otlpexport.Service
}

// New returns the OTLPDestinationService handler.
func New(svc *otlpexport.Service) *Handler { return &Handler{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

// CreateOTLPDestination implements OTLPDestinationServiceHandler.
func (h *Handler) CreateOTLPDestination(ctx context.Context, req *pantherclawv1.CreateOTLPDestinationRequest) (
	*pantherclawv1.CreateOTLPDestinationResponse, error,
) {
	in := otlpexport.NewDestination{Name: req.GetName(), URL: req.GetUrl()}
	for _, hd := range req.GetHeaders() {
		in.Headers = append(in.Headers, otlpexport.Header{Name: hd.GetName(), Value: hd.GetValue()})
	}
	d, err := h.svc.Create(ctx, in)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateOTLPDestinationResponse{Destination: h.proto(d)}, nil
}

// ActivateOTLPDestination implements OTLPDestinationServiceHandler: over
// the API it is always refused (STEP_UP_REQUIRED); a person activates a
// destination on its page with a security key (HR-786).
func (h *Handler) ActivateOTLPDestination(ctx context.Context, req *pantherclawv1.ActivateOTLPDestinationRequest) (
	*pantherclawv1.ActivateOTLPDestinationResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	d, err := h.svc.Activate(ctx, id, nil)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ActivateOTLPDestinationResponse{Destination: h.proto(d)}, nil
}

// DisableOTLPDestination implements OTLPDestinationServiceHandler.
func (h *Handler) DisableOTLPDestination(ctx context.Context, req *pantherclawv1.DisableOTLPDestinationRequest) (
	*pantherclawv1.DisableOTLPDestinationResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	d, err := h.svc.Disable(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DisableOTLPDestinationResponse{Destination: h.proto(d)}, nil
}

// ListOTLPDestinations implements OTLPDestinationServiceHandler.
func (h *Handler) ListOTLPDestinations(ctx context.Context, req *pantherclawv1.ListOTLPDestinationsRequest) (
	*pantherclawv1.ListOTLPDestinationsResponse, error,
) {
	rows, next, err := h.svc.List(ctx, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListOTLPDestinationsResponse{NextPageToken: next}
	for _, d := range rows {
		out.Destinations = append(out.Destinations, h.proto(d))
	}
	return out, nil
}

// GetOTLPDestination implements OTLPDestinationServiceHandler.
func (h *Handler) GetOTLPDestination(ctx context.Context, req *pantherclawv1.GetOTLPDestinationRequest) (
	*pantherclawv1.GetOTLPDestinationResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	d, err := h.svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetOTLPDestinationResponse{Destination: h.proto(d)}, nil
}

// TestOTLPDestination implements OTLPDestinationServiceHandler.
func (h *Handler) TestOTLPDestination(ctx context.Context, req *pantherclawv1.TestOTLPDestinationRequest) (
	*pantherclawv1.TestOTLPDestinationResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Test(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.TestOTLPDestinationResponse{
		Delivered: r.Delivered, Status: int32(r.Status), Code: r.Code, //nolint:gosec // G115: an HTTP status
	}, nil
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func (h *Handler) proto(d otlpexport.Destination) *pantherclawv1.OTLPDestination {
	out := &pantherclawv1.OTLPDestination{
		Id: d.ID.String(), Name: d.Name, Url: d.URL, HeaderNames: d.HeaderNames, State: d.State, CreatedBy: d.CreatedBy,
		CreateTime: timestamppb.New(d.CreatedAt), ActivateTime: ts(d.ActivatedAt), DisableTime: ts(d.DisabledAt),
		ConfirmUrl: h.svc.ConfirmURL(d.ID), CursorSeq: d.CursorSeq, LastSuccessTime: ts(d.LastSuccessAt),
		FailureCount: int32(d.FailureCount), //nolint:gosec // G115: a failure count
		FailingSince: ts(d.FailingSince), LastFailureCode: d.LastFailureCode,
	}
	if d.ActivatedBy != nil {
		out.ActivatedBy = d.ActivatedBy.String()
	}
	return out
}

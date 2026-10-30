// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package siemrpc serves SIEMService over Connect (G0 M10 D35, D36;
// PN-018, F537, HR-259, HR-260).
package siemrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem"
)

// Handler serves SIEMService.
type Handler struct {
	pantherclawv1connect.UnimplementedSIEMServiceHandler
	svc *siem.Service
}

// New returns the SIEMService handler.
func New(svc *siem.Service) *Handler { return &Handler{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

// CreateSIEMDestination implements SIEMServiceHandler.
func (h *Handler) CreateSIEMDestination(ctx context.Context, req *pantherclawv1.CreateSIEMDestinationRequest) (
	*pantherclawv1.CreateSIEMDestinationResponse, error,
) {
	out, err := h.svc.Create(ctx, siem.NewDestination{
		Name: req.GetName(), URL: req.GetUrl(), Internal: req.GetInternal(), DataClasses: req.GetDataClasses(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateSIEMDestinationResponse{Destination: h.proto(out.Destination), SigningSecret: out.Secret}, nil
}

// GetSIEMDestination implements SIEMServiceHandler.
func (h *Handler) GetSIEMDestination(ctx context.Context, req *pantherclawv1.GetSIEMDestinationRequest) (
	*pantherclawv1.GetSIEMDestinationResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	d, err := h.svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetSIEMDestinationResponse{Destination: h.proto(d)}, nil
}

// ListSIEMDestinations implements SIEMServiceHandler.
func (h *Handler) ListSIEMDestinations(ctx context.Context, req *pantherclawv1.ListSIEMDestinationsRequest) (
	*pantherclawv1.ListSIEMDestinationsResponse, error,
) {
	rows, next, err := h.svc.List(ctx, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListSIEMDestinationsResponse{NextPageToken: next}
	for _, d := range rows {
		out.Destinations = append(out.Destinations, h.proto(d))
	}
	return out, nil
}

// SetSIEMDestinationState implements SIEMServiceHandler.
func (h *Handler) SetSIEMDestinationState(ctx context.Context, req *pantherclawv1.SetSIEMDestinationStateRequest) (
	*pantherclawv1.SetSIEMDestinationStateResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	d, err := h.svc.SetState(ctx, id, req.GetState())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetSIEMDestinationStateResponse{Destination: h.proto(d)}, nil
}

// RotateSIEMDestinationSecret implements SIEMServiceHandler.
func (h *Handler) RotateSIEMDestinationSecret(ctx context.Context, req *pantherclawv1.RotateSIEMDestinationSecretRequest) (
	*pantherclawv1.RotateSIEMDestinationSecretResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	secret, err := h.svc.RotateSecret(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RotateSIEMDestinationSecretResponse{SigningSecret: secret}, nil
}

// RetrySIEMDestination implements SIEMServiceHandler.
func (h *Handler) RetrySIEMDestination(ctx context.Context, req *pantherclawv1.RetrySIEMDestinationRequest) (
	*pantherclawv1.RetrySIEMDestinationResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	d, err := h.svc.RetryDestination(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RetrySIEMDestinationResponse{Destination: h.proto(d)}, nil
}

// ListSIEMBatches implements SIEMServiceHandler.
func (h *Handler) ListSIEMBatches(ctx context.Context, req *pantherclawv1.ListSIEMBatchesRequest) (
	*pantherclawv1.ListSIEMBatchesResponse, error,
) {
	id, err := idOf(req.GetDestinationId())
	if err != nil {
		return nil, err
	}
	rows, err := h.svc.Batches(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListSIEMBatchesResponse{}
	for _, b := range rows {
		p := &pantherclawv1.SIEMBatch{
			Id: b.ID.String(), FromSeq: b.FromSeq, ToSeq: b.ToSeq, EventCount: int32(b.EventCount), //nolint:gosec // G115: ≤ 100
			BodyBytes: int32(b.BodyBytes), State: b.State, Attempts: int32(b.Attempts), //nolint:gosec // G115: ≤ 1 MiB, small
			LastStatus: int32(b.LastStatus), LastError: b.LastError, CreateTime: timestamppb.New(b.CreatedAt), //nolint:gosec // G115: HTTP status
			DeliverTime: ts(b.DeliveredAt),
		}
		for _, u := range b.Skipped {
			p.SkippedUids = append(p.SkippedUids, u.String())
		}
		if b.DeliveredAt == nil {
			p.NextAttemptTime = timestamppb.New(b.NextAttemptAt)
		}
		out.Batches = append(out.Batches, p)
	}
	return out, nil
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func (h *Handler) proto(d siem.Destination) *pantherclawv1.SIEMDestination {
	out := &pantherclawv1.SIEMDestination{
		Id: d.ID.String(), Name: d.Name, Url: d.URL, Internal: d.Internal, DataClasses: d.DataClasses, Format: d.Format,
		State: d.State, CreatedBy: d.CreatedBy, CreateTime: timestamppb.New(d.CreatedAt), ActivateTime: ts(d.ActivatedAt),
		ConfirmUrl: h.svc.ConfirmURL(d.ID), Health: d.Health, ConfirmTime: ts(d.ConfirmedAt), CursorSeq: d.CursorSeq,
		LastDeliveredSeq: d.LastDeliveredSeq, LastDeliveredTime: ts(d.LastDeliveredAt),
		ConsecutiveFailures: int32(d.ConsecutiveFailures), //nolint:gosec // G115: a failure count
		FailingSince:        ts(d.FailingSince), LastFailureCode: d.LastFailureCode, DeliveredBatches: d.DeliveredBatches,
		FailedBatches: d.FailedBatches, Retries: d.Retries, WaitingSince: ts(d.WaitingSince), RotationEndTime: ts(d.RotationEndsAt),
		SignatureScheme: d.SignatureScheme,
	}
	if d.ActivatedBy != nil {
		out.ActivatedBy = d.ActivatedBy.String()
	}
	return out
}

// SetSIEMDestinationSignatureScheme implements SIEMServiceHandler (G0 M20
// D251).
func (h *Handler) SetSIEMDestinationSignatureScheme(ctx context.Context, req *pantherclawv1.SetSIEMDestinationSignatureSchemeRequest) (
	*pantherclawv1.SetSIEMDestinationSignatureSchemeResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	d, jwks, err := h.svc.SetSignatureScheme(ctx, id, req.GetSignatureScheme())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetSIEMDestinationSignatureSchemeResponse{Destination: h.proto(d), JwksUrl: jwks}, nil
}

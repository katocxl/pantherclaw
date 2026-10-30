// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package exportsrpc serves ExportDestinationService over Connect (G0 M20
// D252; F517, HR-513..516).
package exportsrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/exports"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/sigv4"
)

// Handler serves ExportDestinationService.
type Handler struct {
	pantherclawv1connect.UnimplementedExportDestinationServiceHandler
	svc *exports.Service
}

// New returns the ExportDestinationService handler.
func New(svc *exports.Service) *Handler { return &Handler{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

func credentialOf(c *pantherclawv1.ExportCredential) exports.Credential {
	return exports.Credential{
		BearerToken: c.GetBearerToken(),
		S3:          sigv4.Credentials{AccessKeyID: c.GetAccessKeyId(), SecretAccessKey: c.GetSecretAccessKey()},
	}
}

// CreateExportDestination implements ExportDestinationServiceHandler.
func (h *Handler) CreateExportDestination(ctx context.Context, req *pantherclawv1.CreateExportDestinationRequest) (
	*pantherclawv1.CreateExportDestinationResponse, error,
) {
	d, err := h.svc.Create(ctx, exports.NewDestination{
		Name: req.GetName(), DataClasses: req.GetDataClasses(), Credential: credentialOf(req.GetCredential()),
		Target: exports.Target{
			Kind: req.GetKind(), URL: req.GetUrl(), Bucket: req.GetBucket(), Region: req.GetRegion(), KeyPrefix: req.GetKeyPrefix(),
			PathStyle: req.GetPathStyle(), Internal: req.GetInternal(),
		},
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateExportDestinationResponse{Destination: h.proto(d)}, nil
}

// GetExportDestination implements ExportDestinationServiceHandler.
func (h *Handler) GetExportDestination(ctx context.Context, req *pantherclawv1.GetExportDestinationRequest) (
	*pantherclawv1.GetExportDestinationResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	d, err := h.svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetExportDestinationResponse{Destination: h.proto(d)}, nil
}

// ListExportDestinations implements ExportDestinationServiceHandler.
func (h *Handler) ListExportDestinations(ctx context.Context, req *pantherclawv1.ListExportDestinationsRequest) (
	*pantherclawv1.ListExportDestinationsResponse, error,
) {
	rows, next, err := h.svc.List(ctx, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListExportDestinationsResponse{NextPageToken: next}
	for _, d := range rows {
		out.Destinations = append(out.Destinations, h.proto(d))
	}
	return out, nil
}

// SetExportDestinationState implements ExportDestinationServiceHandler.
func (h *Handler) SetExportDestinationState(ctx context.Context, req *pantherclawv1.SetExportDestinationStateRequest) (
	*pantherclawv1.SetExportDestinationStateResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	d, err := h.svc.SetState(ctx, id, req.GetState())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetExportDestinationStateResponse{Destination: h.proto(d)}, nil
}

// ReplaceExportDestinationCredential implements ExportDestinationServiceHandler.
func (h *Handler) ReplaceExportDestinationCredential(ctx context.Context, req *pantherclawv1.ReplaceExportDestinationCredentialRequest) (
	*pantherclawv1.ReplaceExportDestinationCredentialResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	d, err := h.svc.ReplaceCredential(ctx, id, credentialOf(req.GetCredential()))
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ReplaceExportDestinationCredentialResponse{Destination: h.proto(d)}, nil
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func (h *Handler) proto(d exports.Destination) *pantherclawv1.ExportDestination {
	out := &pantherclawv1.ExportDestination{
		Id: d.ID.String(), Name: d.Name, Kind: d.Kind, Url: d.URL, Bucket: d.Bucket, Region: d.Region, KeyPrefix: d.KeyPrefix,
		PathStyle: d.PathStyle, Internal: d.Internal, DataClasses: d.DataClasses, State: d.State, CreatedBy: d.CreatedBy,
		CreateTime: timestamppb.New(d.CreatedAt), ActivateTime: ts(d.ActivatedAt), ConfirmUrl: h.svc.ConfirmURL(d.ID), Health: d.Health,
		ConfirmTime: ts(d.ConfirmedAt), LastDeliveredTime: ts(d.LastDeliveredAt),
		ConsecutiveFailures: int32(d.ConsecutiveFailures), //nolint:gosec // G115: a failure count
		FailingSince:        ts(d.FailingSince), LastFailureCode: d.LastFailureCode, DeliveredPushes: d.DeliveredPushes,
		FailedPushes: d.FailedPushes, CredentialReplaceTime: ts(d.SecretReplacedAt),
	}
	if d.ActivatedBy != nil {
		out.ActivatedBy = d.ActivatedBy.String()
	}
	return out
}

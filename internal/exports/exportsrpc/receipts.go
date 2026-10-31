// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package exportsrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/exports"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// PushExportArtifact implements ExportDestinationServiceHandler.
func (h *Handler) PushExportArtifact(ctx context.Context, req *pantherclawv1.PushExportArtifactRequest) (
	*pantherclawv1.PushExportArtifactResponse, error,
) {
	dest, err := idOf(req.GetDestinationId())
	if err != nil {
		return nil, err
	}
	in := exports.PushRequest{Destination: dest, Class: req.GetClass(), Stream: req.GetStream(), FromSeq: req.GetFromSeq(), ToSeq: req.GetToSeq()}
	if v := req.GetArtifactId(); v != "" {
		if in.Artifact, err = idOf(v); err != nil {
			return nil, err
		}
	}
	r, err := h.svc.Push(ctx, in)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.PushExportArtifactResponse{Receipt: receiptProto(r)}, nil
}

// GetExportReceipt implements ExportDestinationServiceHandler.
func (h *Handler) GetExportReceipt(ctx context.Context, req *pantherclawv1.GetExportReceiptRequest) (
	*pantherclawv1.GetExportReceiptResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.svc.GetReceipt(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetExportReceiptResponse{Receipt: receiptProto(r)}, nil
}

// ListExportReceipts implements ExportDestinationServiceHandler.
func (h *Handler) ListExportReceipts(ctx context.Context, req *pantherclawv1.ListExportReceiptsRequest) (
	*pantherclawv1.ListExportReceiptsResponse, error,
) {
	var dest ids.UUID
	if v := req.GetDestinationId(); v != "" {
		var err error
		if dest, err = idOf(v); err != nil {
			return nil, err
		}
	}
	rows, next, err := h.svc.ListReceipts(ctx, dest, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListExportReceiptsResponse{NextPageToken: next}
	for _, r := range rows {
		out.Receipts = append(out.Receipts, receiptProto(r))
	}
	return out, nil
}

func receiptProto(r exports.Receipt) *pantherclawv1.ExportReceipt {
	out := &pantherclawv1.ExportReceipt{
		Id: r.ID.String(), DestinationId: r.Destination.String(), DestinationName: r.DestinationName, Class: r.Class, Streamed: r.Streamed,
		FromSeq: r.FromSeq, ToSeq: r.ToSeq, RequestedBy: r.RequestedBy.String(), ObjectKey: r.ObjectKey, State: r.State, AbortState: r.AbortState,
		SizeBytes: r.SizeBytes, Sha256: r.SHA256, Parts: int32(r.Parts), Etag: r.ETag, //nolint:gosec // G115: at most 10000 parts
		Attempts: int32(r.Attempts), LastStatus: int32(r.LastStatus), FailureCode: r.FailureCode, //nolint:gosec // G115: small numbers
		CreateTime: timestamppb.New(r.CreatedAt), DeliverTime: ts(r.DeliveredAt), RemovedHereTime: ts(r.RemovedHereAt),
		NoticeState: r.NoticeState, NoticeKey: r.NoticeKey, NoticeSendTime: ts(r.NoticeSentAt), Status: r.Status,
	}
	if r.Artifact != nil {
		out.ArtifactId = r.Artifact.String()
	}
	return out
}

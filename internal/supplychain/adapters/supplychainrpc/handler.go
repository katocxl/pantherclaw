// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package supplychainrpc serves SupplyChainService over Connect (G0 M24 D212).
// Handlers only translate: authentication, the coarse permission check and
// protovalidate have run before a handler is called.
package supplychainrpc

import (
	"context"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/supplychain/adapters/pgflags"
	"github.com/katocxl/pantherclaw/internal/supplychain/app"
)

// Handler serves SupplyChainService.
type Handler struct {
	pantherclawv1connect.UnimplementedSupplyChainServiceHandler
	svc *app.Service
}

// New returns the SupplyChainService handler.
func New(svc *app.Service) *Handler { return &Handler{svc: svc} }

// optional parses an id that may be left out.
func optional(s string) (*ids.UUID, error) {
	if s == "" {
		return nil, nil //nolint:nilnil // no filter is an answer
	}
	id, err := ids.ParseUUID(s)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, "invalid id")
	}
	return &id, nil
}

func idString(id *ids.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// flagOf is a flag as the API shows it.
func flagOf(r dbq.PcSupplychainFlag) *pb.SupplyChainFlag {
	note, spans, reason := pgflags.Detail(r.Detail)
	out := &pb.SupplyChainFlag{
		Id: r.ID.String(), ConnectionId: idString(r.ConnectionID), InventoryItemId: idString(r.InventoryID),
		PackageVersionId: idString(r.PackageVersionID), Tool: r.Tool, Digest: r.Digest, CheckKind: r.CheckKind, Severity: r.Severity,
		Note: note, Reason: reason, State: r.State, FirstSeenTime: timestamppb.New(r.FirstSeen), LastSeenTime: timestamppb.New(r.LastSeen),
	}
	for _, s := range spans {
		out.Spans = append(out.Spans, &pb.SupplyChainFlagSpan{
			Field: string(s.Field), Start: int32(s.Start), End: int32(s.End), //nolint:gosec // G115: offsets into at most 64 KiB
		})
	}
	return out
}

// ListSupplyChainFlags implements SupplyChainServiceHandler.
func (h *Handler) ListSupplyChainFlags(ctx context.Context, req *pb.ListSupplyChainFlagsRequest) (*pb.ListSupplyChainFlagsResponse, error) {
	var f app.Filter
	var err error
	if f.Connection, err = optional(req.GetConnectionId()); err != nil {
		return nil, err
	}
	if f.Item, err = optional(req.GetInventoryItemId()); err != nil {
		return nil, err
	}
	if f.Version, err = optional(req.GetPackageVersionId()); err != nil {
		return nil, err
	}
	f.States = req.GetStates()
	rows, next, err := h.svc.List(ctx, f, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pb.ListSupplyChainFlagsResponse{NextPageToken: next}
	for _, r := range rows {
		out.Flags = append(out.Flags, flagOf(r))
	}
	return out, nil
}

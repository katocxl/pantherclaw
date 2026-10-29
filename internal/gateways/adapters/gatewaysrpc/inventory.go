// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"

	"connectrpc.com/connect/v2"

	connapp "github.com/katocxl/pantherclaw/internal/connections/app"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Inventories records a gateway's discovery inventory reports (connections
// app).
type Inventories interface {
	ReportInventory(ctx context.Context, org ids.OrgID, gateway ids.UUID, r connapp.InventoryReport) (int32, error)
}

// WithInventories serves ReportInventory from i.
func (h *GatewayHandler) WithInventories(i Inventories) *GatewayHandler {
	h.inventories = i
	return h
}

// ReportInventory implements GatewayServiceHandler, on the mTLS listener
// only (gateway.observe): what the upstream MCP server behind one of the
// calling gateway's connections lists (F352, G0 M15 D20). The org and the
// gateway come from the certificate alone (HR-418).
func (h *GatewayHandler) ReportInventory(ctx context.Context, req *pb.ReportInventoryRequest) (*pb.ReportInventoryResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	if h.inventories == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, "inventory reports are not served here")
	}
	conn, err := ids.ParseUUID(req.GetConnectionId())
	if err != nil {
		return nil, errInvalidID
	}
	r := connapp.InventoryReport{Connection: conn, Complete: req.GetComplete()}
	for _, t := range req.GetTools() {
		r.Entries = append(r.Entries, connapp.InventoryEntry{
			Kind: connapp.InventoryTool, Name: t.GetName(), Digest: t.GetDigest(), Description: t.GetDescription(),
			DescriptionTruncated: t.GetDescriptionTruncated(),
		})
	}
	for _, x := range req.GetResources() {
		r.Entries = append(r.Entries, connapp.InventoryEntry{
			Kind: connapp.InventoryResource, Name: x.GetUri(), DisplayName: x.GetName(), MimeType: x.GetMimeType(), Digest: x.GetDigest(),
			Description: x.GetDescription(), DescriptionTruncated: x.GetDescriptionTruncated(),
		})
	}
	for _, x := range req.GetResourceTemplates() {
		r.Entries = append(r.Entries, connapp.InventoryEntry{
			Kind: connapp.InventoryTemplate, Name: x.GetUriTemplate(), DisplayName: x.GetName(), MimeType: x.GetMimeType(),
			Digest: x.GetDigest(), Description: x.GetDescription(), DescriptionTruncated: x.GetDescriptionTruncated(),
		})
	}
	n, err := h.inventories.ReportInventory(ctx, id.Org, id.Gateway, r)
	if err != nil {
		return nil, err
	}
	return &pb.ReportInventoryResponse{NewItems: n}, nil
}

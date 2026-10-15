// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"

	"connectrpc.com/connect/v2"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Drifts records a gateway's upstream drift reports (connections app).
type Drifts interface {
	ReportDriftDescribed(ctx context.Context, org ids.OrgID, gateway, connection ids.UUID, tool, expected, observed string,
		description *string) (bool, error)
}

// WithDrifts serves ReportDrift from d.
func (h *GatewayHandler) WithDrifts(d Drifts) *GatewayHandler {
	h.drifts = d
	return h
}

// ReportDrift implements GatewayServiceHandler, on the mTLS listener only
// (gateway.observe): an upstream MCP server behind one of the calling
// gateway's connections announces a tool that no longer matches the
// reviewed definition, and the server quarantines the org's pinned package
// version (HR-081). The org and the gateway come from the certificate
// alone.
func (h *GatewayHandler) ReportDrift(ctx context.Context, req *pb.ReportDriftRequest) (*pb.ReportDriftResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	if h.drifts == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, "drift reports are not served here")
	}
	conn, err := ids.ParseUUID(req.GetConnectionId())
	if err != nil {
		return nil, errInvalidID
	}
	quarantined, err := h.drifts.ReportDriftDescribed(ctx, id.Org, id.Gateway, conn, req.GetTool(), req.GetExpectedDigest(),
		req.GetObservedDigest(), req.ObservedDescription)
	if err != nil {
		return nil, err
	}
	return &pb.ReportDriftResponse{Quarantined: quarantined}, nil
}

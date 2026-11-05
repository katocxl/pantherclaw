// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"

	"connectrpc.com/connect/v2"

	bsapp "github.com/katocxl/pantherclaw/internal/browsersites/app"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// PageCompares records a gateway's cloaking compare reports (G0 M33 D986).
type PageCompares interface {
	ReportPageCompare(ctx context.Context, org ids.OrgID, gateway, connection ids.UUID, in bsapp.PageCompare) (bool, error)
}

// WithPageCompares serves ReportPageCompare from p.
func (h *GatewayHandler) WithPageCompares(p PageCompares) *GatewayHandler {
	h.pageCompares = p
	return h
}

// ReportPageCompare implements GatewayServiceHandler, on the mTLS listener
// only (gateway.observe): a cloaking compare mismatch on a browser site
// marked for the compare (HR-750). The org and the gateway come from the
// certificate alone; the connection must be one the gateway serves.
func (h *GatewayHandler) ReportPageCompare(ctx context.Context, req *pb.ReportPageCompareRequest) (*pb.ReportPageCompareResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	if h.pageCompares == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, "page compare reports are not served here")
	}
	conn, err := ids.ParseUUID(req.GetConnectionId())
	if err != nil {
		return nil, errInvalidID
	}
	in := bsapp.PageCompare{
		Host: req.GetHost(), PathSHA256: req.GetPathSha256(), AgentStatus: req.GetAgentStatus(), PlainStatus: req.GetPlainStatus(),
		AgentBytes: req.GetAgentBytes(), PlainBytes: req.GetPlainBytes(), SimilarityPermille: req.GetSimilarityPermille(),
	}
	if r := req.GetRunId(); r != "" {
		if in.Run, err = ids.ParseUUID(r); err != nil {
			return nil, errInvalidID
		}
	}
	if t := req.GetTransactionId(); t != "" {
		if in.Transaction, err = ids.ParseUUID(t); err != nil {
			return nil, errInvalidID
		}
	}
	recorded, err := h.pageCompares.ReportPageCompare(ctx, id.Org, id.Gateway, conn, in)
	if err != nil {
		return nil, err
	}
	return &pb.ReportPageCompareResponse{Recorded: recorded}, nil
}

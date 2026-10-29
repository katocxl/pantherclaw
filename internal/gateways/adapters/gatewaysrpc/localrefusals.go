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

// LocalRefusals records actions a gateway refused on its own.
type LocalRefusals interface {
	ReportLocalRefusal(ctx context.Context, org ids.OrgID, gateway, connection ids.UUID, code, operation string, run ids.UUID, detail connapp.RefusalDetail) error
}

// WithLocalRefusals serves ReportLocalRefusal from r.
func (h *GatewayHandler) WithLocalRefusals(r LocalRefusals) *GatewayHandler {
	h.localRefusals = r
	return h
}

// ReportLocalRefusal implements GatewayServiceHandler, on the mTLS
// listener only (G0 M12, HR-225; G0 M15 D40): a secret_in_payload or
// elicitation_refused refusal is audited,
// with machine metadata only, for a connection the gateway serves, so
// detections see it.
func (h *GatewayHandler) ReportLocalRefusal(ctx context.Context, req *pb.ReportLocalRefusalRequest) (*pb.ReportLocalRefusalResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	if h.localRefusals == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, "local refusal reports are not served here")
	}
	conn, err := ids.ParseUUID(req.GetConnectionId())
	if err != nil {
		return nil, errInvalidID
	}
	var run ids.UUID
	if req.GetRunId() != "" {
		if run, err = ids.ParseUUID(req.GetRunId()); err != nil {
			return nil, errInvalidID
		}
	}
	if err := h.localRefusals.ReportLocalRefusal(ctx, id.Org, id.Gateway, conn, req.GetCode(), req.GetOperation(), run, connapp.RefusalDetail{
		ElicitationReason: req.GetElicitationReason(), QuestionSHA256: req.GetQuestionSha256(),
	}); err != nil {
		return nil, err
	}
	return &pb.ReportLocalRefusalResponse{}, nil
}

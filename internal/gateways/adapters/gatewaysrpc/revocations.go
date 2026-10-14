// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"
	"time"

	"connectrpc.com/connect/v2"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Revocations records an installation token a gateway could not revoke.
type Revocations interface {
	ReportRevocationFailure(ctx context.Context, org ids.OrgID, gateway, connection ids.UUID, purpose string, installation int64,
		repository string, expires time.Time) error
}

// WithRevocations serves ReportRevocationFailure from r.
func (h *GatewayHandler) WithRevocations(r Revocations) *GatewayHandler {
	h.revocations = r
	return h
}

// ReportRevocationFailure implements GatewayServiceHandler, on the mTLS
// listener only (ADR-0021 item 6, R-18): a fact read's, a verification
// read's or a scan's token that stays valid until its expiry is audited as
// credential.revoke_failed, for a connection the gateway serves.
func (h *GatewayHandler) ReportRevocationFailure(ctx context.Context, req *pb.ReportRevocationFailureRequest) (*pb.ReportRevocationFailureResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	if h.revocations == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, "revocation reports are not served here")
	}
	conn, err := ids.ParseUUID(req.GetConnectionId())
	if err != nil {
		return nil, errInvalidID
	}
	var expires time.Time
	if req.GetExpireTime() != nil {
		expires = req.GetExpireTime().AsTime()
	}
	if err := h.revocations.ReportRevocationFailure(ctx, id.Org, id.Gateway, conn, req.GetPurpose(), req.GetInstallationId(),
		req.GetRepository(), expires); err != nil {
		return nil, err
	}
	return &pb.ReportRevocationFailureResponse{}, nil
}

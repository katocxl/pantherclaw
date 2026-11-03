// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"

	"connectrpc.com/connect/v2"

	capp "github.com/katocxl/pantherclaw/internal/campaigns/app"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ModelCalls decides and counts the calls of the gateway's model face.
type ModelCalls interface {
	AuthorizeModelCall(ctx context.Context, org ids.OrgID, in capp.ModelCall) (ids.UUID, error)
	ReportModelUsage(ctx context.Context, org ids.OrgID, gateway, campaign, run ids.UUID, bytes int64) error
}

// WithModelCalls serves AuthorizeModelCall and ReportModelUsage from m.
func (h *GatewayHandler) WithModelCalls(m ModelCalls) *GatewayHandler {
	h.modelCalls = m
	return h
}

// AuthorizeModelCall implements GatewayServiceHandler, on the mTLS listener
// only (G0 M25 D313): the org and gateway come from the certificate.
func (h *GatewayHandler) AuthorizeModelCall(ctx context.Context, req *pb.AuthorizeModelCallRequest) (*pb.AuthorizeModelCallResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	if h.modelCalls == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, "model calls are not served here")
	}
	conn, err := ids.ParseUUID(req.GetConnectionId())
	if err != nil {
		return nil, errInvalidID
	}
	run, err := ids.ParseUUID(req.GetRunId())
	if err != nil {
		return nil, errInvalidID
	}
	campaign, err := h.modelCalls.AuthorizeModelCall(ctx, id.Org, capp.ModelCall{
		Gateway: id.Gateway, Connection: conn, Run: run, ModelHost: req.GetModelHost(), BytesToModel: req.GetBytesToModel(),
	})
	if err != nil {
		return nil, err
	}
	return &pb.AuthorizeModelCallResponse{CampaignId: campaign.String()}, nil
}

// ReportModelUsage implements GatewayServiceHandler, on the mTLS listener
// only (G0 M25 D313): counts, never content.
func (h *GatewayHandler) ReportModelUsage(ctx context.Context, req *pb.ReportModelUsageRequest) (*pb.ReportModelUsageResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	if h.modelCalls == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, "model calls are not served here")
	}
	campaign, err := ids.ParseUUID(req.GetCampaignId())
	if err != nil {
		return nil, errInvalidID
	}
	run, err := ids.ParseUUID(req.GetRunId())
	if err != nil {
		return nil, errInvalidID
	}
	if err := h.modelCalls.ReportModelUsage(ctx, id.Org, id.Gateway, campaign, run, req.GetBytesFromModel()); err != nil {
		return nil, err
	}
	return &pb.ReportModelUsageResponse{}, nil
}

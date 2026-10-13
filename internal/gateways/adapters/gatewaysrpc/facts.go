// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/facts/adapters/factsrpc"
	factsapp "github.com/katocxl/pantherclaw/internal/facts/app"
	"github.com/katocxl/pantherclaw/internal/facts/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Facts records what a gateway reads as a connection's fact provider (G0
// M8 decision 5).
type Facts interface {
	PutGatewayFacts(ctx context.Context, org ids.OrgID, gateway, connection ids.UUID, obs []domain.Observation) ([]factsapp.Result, error)
}

// WithFacts serves ReportFacts from f.
func (h *GatewayHandler) WithFacts(f Facts) *GatewayHandler {
	h.facts = f
	return h
}

// ReportFacts implements GatewayServiceHandler, on the mTLS listener only
// (gateway.facts.report): the org and the gateway come from the
// certificate, and only the provider bound to that gateway and connection
// may report, for the facts it declares (HR-160).
func (h *GatewayHandler) ReportFacts(ctx context.Context, req *pb.ReportFactsRequest) (*pb.ReportFactsResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	if h.facts == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, "facts are not served here")
	}
	conn, err := ids.ParseUUID(req.GetConnectionId())
	if err != nil {
		return nil, errInvalidID
	}
	results, err := h.facts.PutGatewayFacts(ctx, id.Org, id.Gateway, conn, factsrpc.ObservationsOf(req.GetObservations()))
	if err != nil {
		return nil, err
	}
	return &pb.ReportFactsResponse{Results: factsrpc.ResultsOf(results)}, nil
}

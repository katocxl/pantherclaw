// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package agentsrpc

import (
	"context"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/authority"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// GatewayScans serves AgentService.SubmitScanFindings on the gateway
// listener (G0 M8, HR-209): a gateway submits its organization scan's
// findings while it holds the scan's org_scan lease; the org and the
// gateway come from its certificate (HR-020). Nothing else of
// AgentService is served there.
type GatewayScans struct {
	pantherclawv1connect.UnimplementedAgentServiceHandler
	inv *app.Inventory
}

// NewGatewayScans returns the handler.
func NewGatewayScans(inv *app.Inventory) *GatewayScans { return &GatewayScans{inv: inv} }

var errScanRequired = pcerr.New(pcerr.InvalidArgument, "SCAN_ID", "a gateway names the scan its findings are from")

// SubmitScanFindings implements AgentServiceHandler.
func (s *GatewayScans) SubmitScanFindings(ctx context.Context, req *pantherclawv1.SubmitScanFindingsRequest) (*pantherclawv1.SubmitScanFindingsResponse, error) {
	gw, ok := authority.GatewayFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, "gateway credentials required")
	}
	gateway, err := ids.ParseUUID(gw.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, "gateway credentials required")
	}
	scan, err := ids.ParseUUID(req.GetScanId())
	if err != nil {
		return nil, errScanRequired
	}
	findings, err := findingsOf(req)
	if err != nil {
		return nil, err
	}
	r, err := s.inv.SubmitGitHubScan(ctx, gw.Org, gateway, scan, findings)
	if err != nil {
		return nil, err
	}
	return scanResult(r), nil
}

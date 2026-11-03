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
	saas "github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
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

// errScopeGateway refuses a CI-mode scope on an org scan: an org scan counts
// its misses from its own report (D114, D115).
var errScopeGateway = pcerr.New(pcerr.InvalidArgument, "SCAN_SCOPE", "an organization scan has no scope; only a CI-mode scan sets scope and complete")

// isSaaSFinding reports whether the first finding is of a SaaS kind. The
// writers refuse a mix: each takes only its own kinds.
func isSaaSFinding(findings []app.ScanFinding) bool {
	if len(findings) == 0 {
		return false
	}
	_, ok := saas.Attributes(findings[0].Kind)
	return ok
}

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
	if req.GetScope() != "" || req.GetComplete() {
		return nil, errScopeGateway
	}
	findings, err := findingsOf(req)
	if err != nil {
		return nil, err
	}
	submit := s.inv.SubmitGitHubScan
	if isSaaSFinding(findings) {
		submit = s.inv.SubmitSaaSScan // a SaaS scan's own lease and writer (G0 M26 D407)
	}
	r, err := submit(ctx, gw.Org, gateway, scan, req.GetLease(), findings)
	if err != nil {
		return nil, err
	}
	return scanResult(r), nil
}

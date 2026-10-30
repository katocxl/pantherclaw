// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/hosting/adapters/hostingrpc"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m19HostingProcedures are the hosted gateway procedures (G0 M19 D203): an
// org's people manage its hosted gateway on the public API; host agents
// call HostingAgentService on the gateway listener with their host
// certificate only (hostingrpc.HostAuthenticator), which the gateway
// listener's own authenticator never admits (hosting.agent is not a
// gateway permission, HR-500).
var m19HostingProcedures = map[string]td.Permission{
	pantherclawv1connect.HostedGatewayServiceRequestHostedGatewayProcedure:     "gateway.manage",
	pantherclawv1connect.HostedGatewayServiceGetHostedGatewayProcedure:         "gateway.read",
	pantherclawv1connect.HostedGatewayServiceListHostedGatewaysProcedure:       "gateway.read",
	pantherclawv1connect.HostedGatewayServiceDeprovisionHostedGatewayProcedure: "gateway.manage",
	// A hosted gateway, by its own certificate (D210).
	pantherclawv1connect.HostedGatewayIdentityServiceIssueServerCertificateProcedure: "gateway.sync",
}

// m19HostingClasses are the org procedures' plan-gate classes (G0 UI D43).
// HostingAgentService is never gated: a host is no org caller (HR-500).
var m19HostingClasses = map[string]entitlements.Class{
	pantherclawv1connect.HostedGatewayServiceRequestHostedGatewayProcedure:     entitlements.ClassChange,
	pantherclawv1connect.HostedGatewayServiceGetHostedGatewayProcedure:         entitlements.ClassRead,
	pantherclawv1connect.HostedGatewayServiceListHostedGatewaysProcedure:       entitlements.ClassRead,
	pantherclawv1connect.HostedGatewayServiceDeprovisionHostedGatewayProcedure: entitlements.ClassSafety,
}

func init() {
	maps.Copy(procedurePermissions, m19HostingProcedures)
	maps.Copy(procedurePermissions, hostingrpc.AgentProcedures)
	maps.Copy(procedureClasses, m19HostingClasses)
}

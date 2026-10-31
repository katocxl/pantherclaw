// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m24AgentProcedures are the agent card (G0 M24 D231), with the same
// permission as reading the agent, and the gateway's card signing (D232).
var m24AgentProcedures = map[string]td.Permission{
	pantherclawv1connect.AgentServiceGetAgentCardProcedure:    td.PermAgentRead,
	pantherclawv1connect.GatewayServiceSignAgentCardProcedure: td.PermGatewaySync,
}

var m24AgentClasses = map[string]entitlements.Class{
	pantherclawv1connect.AgentServiceGetAgentCardProcedure: entitlements.ClassRead,
}

// m24AlternatePermissions lets a Scanner reach SubmitScanFindings without
// agent.manage (G0 M24 D236); the use case holds it to one device's scope
// (HR-589). The gateway listener has none of these.
var m24AlternatePermissions = map[string]td.Permission{
	pantherclawv1connect.AgentServiceSubmitScanFindingsProcedure: td.PermAgentScanSubmit,
}

func init() {
	maps.Copy(procedurePermissions, m24AgentProcedures)
	maps.Copy(procedureClasses, m24AgentClasses)
}

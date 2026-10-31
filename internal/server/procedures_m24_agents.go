// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m24AgentProcedures is the agent card (G0 M24 D231): the same permission as
// reading the agent.
var m24AgentProcedures = map[string]td.Permission{
	pantherclawv1connect.AgentServiceGetAgentCardProcedure: td.PermAgentRead,
}

var m24AgentClasses = map[string]entitlements.Class{
	pantherclawv1connect.AgentServiceGetAgentCardProcedure: entitlements.ClassRead,
}

func init() {
	maps.Copy(procedurePermissions, m24AgentProcedures)
	maps.Copy(procedureClasses, m24AgentClasses)
}

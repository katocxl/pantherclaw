// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m27BehaviorProcedures are BehaviorService's procedures (G0 M27 D501, D502).
// Reading needs behavior.read somewhere; the use case then holds to the
// agents in the viewer's scope.
var m27BehaviorProcedures = map[string]td.Permission{
	pantherclawv1connect.BehaviorServiceGetAgentProfileProcedure:    td.PermBehaviorRead,
	pantherclawv1connect.BehaviorServiceGetBehaviorContextProcedure: td.PermBehaviorRead,
}

func init() { maps.Copy(procedurePermissions, m27BehaviorProcedures) }

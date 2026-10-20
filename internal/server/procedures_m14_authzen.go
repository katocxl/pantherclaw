// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// enforcementPointProcedures are EnforcementPointService's procedures (G0
// M14 D29, D62): all need enforcement_point.manage; the use cases refuse
// every change by a caller who is not a person, and activation answers
// STEP_UP_REQUIRED here and happens on the confirm page.
var enforcementPointProcedures = map[string]td.Permission{
	pantherclawv1connect.EnforcementPointServiceCreateEnforcementPointProcedure:            td.PermEnforcementPointManage,
	pantherclawv1connect.EnforcementPointServiceActivateEnforcementPointProcedure:          td.PermEnforcementPointManage,
	pantherclawv1connect.EnforcementPointServiceUpdateEnforcementPointConnectionsProcedure: td.PermEnforcementPointManage,
	pantherclawv1connect.EnforcementPointServiceDisableEnforcementPointProcedure:           td.PermEnforcementPointManage,
	pantherclawv1connect.EnforcementPointServiceGetEnforcementPointProcedure:               td.PermEnforcementPointManage,
	pantherclawv1connect.EnforcementPointServiceListEnforcementPointsProcedure:             td.PermEnforcementPointManage,
}

func init() { maps.Copy(procedurePermissions, enforcementPointProcedures) }

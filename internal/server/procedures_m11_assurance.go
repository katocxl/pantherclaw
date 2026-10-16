// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// automationAssuranceProcedures are AssuranceService's procedures (G0 M11
// part 2 D34–D38, D59): changing tests and starting runs or simulations is
// automation.manage, reads are automation.read; reach previews also need
// exposure.read where each agent lives, which the use case checks.
var automationAssuranceProcedures = map[string]td.Permission{
	pantherclawv1connect.AssuranceServiceSetTestCasesProcedure:              td.PermAutomationManage,
	pantherclawv1connect.AssuranceServiceListTestCasesProcedure:             td.PermAutomationRead,
	pantherclawv1connect.AssuranceServiceRunTestsProcedure:                  td.PermAutomationManage,
	pantherclawv1connect.AssuranceServiceGetTestRunProcedure:                td.PermAutomationRead,
	pantherclawv1connect.AssuranceServiceStartAutomationSimulationProcedure: td.PermAutomationManage,
	pantherclawv1connect.AssuranceServiceGetAutomationSimulationProcedure:   td.PermAutomationRead,
	pantherclawv1connect.AssuranceServiceGetRolloutReportProcedure:          td.PermAutomationRead,
	pantherclawv1connect.AssuranceServiceGetAutomationStatusProcedure:       td.PermAutomationRead,
	pantherclawv1connect.AssuranceServiceInspectVersionProcedure:            td.PermAutomationRead,
	pantherclawv1connect.AssuranceServicePreviewBlastRadiusProcedure:        td.PermAutomationRead,
	pantherclawv1connect.AssuranceServiceCompareRestrictionProcedure:        td.PermAutomationRead,
	pantherclawv1connect.AssuranceServiceGetAutomationMetricsProcedure:      td.PermAutomationRead,
}

func init() { maps.Copy(procedurePermissions, automationAssuranceProcedures) }

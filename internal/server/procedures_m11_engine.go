// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// automationEngineProcedures are ExecutionService's and
// AutomationLaunchService's procedures (G0 M11 part 2 D26, D28, D29):
// reads are automation.read, cancelling is automation.manage (human
// only); the launch procedures are workload-authenticated by PAP/1 in
// their handler, like WorkloadService.
var automationEngineProcedures = map[string]td.Permission{
	pantherclawv1connect.ExecutionServiceGetExecutionProcedure:           td.PermAutomationRead,
	pantherclawv1connect.ExecutionServiceListExecutionsProcedure:         td.PermAutomationRead,
	pantherclawv1connect.ExecutionServiceLookupExecutionProcedure:        td.PermAutomationRead,
	pantherclawv1connect.ExecutionServiceCancelExecutionProcedure:        td.PermAutomationManage,
	pantherclawv1connect.ExecutionServiceCancelActiveExecutionsProcedure: td.PermAutomationManage,
	pantherclawv1connect.AutomationLaunchServiceClaimLaunchProcedure:     td.PermWorkloadRun,
	pantherclawv1connect.AutomationLaunchServiceCompleteLaunchProcedure:  td.PermWorkloadRun,
}

func init() { maps.Copy(procedurePermissions, automationEngineProcedures) }

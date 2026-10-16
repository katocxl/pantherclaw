// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// triggersProcedures are TriggerService's procedures (G0 M11 part 2
// D16–D23, D53): reads need automation.read; starts need automation.run;
// sources and destinations need automation.endpoints.manage (all human
// only, checked again by the use cases with the Team edition). Activation,
// rotation and step-up starts answer STEP_UP_REQUIRED here and happen on
// the pages.
var triggersProcedures = map[string]td.Permission{
	pantherclawv1connect.TriggerServicePreviewScheduleProcedure:                   td.PermAutomationRead,
	pantherclawv1connect.TriggerServiceStartExecutionProcedure:                    td.PermAutomationRun,
	pantherclawv1connect.TriggerServiceRetryExecutionProcedure:                    td.PermAutomationRun,
	pantherclawv1connect.TriggerServiceGetTriggerProcedure:                        td.PermAutomationRead,
	pantherclawv1connect.TriggerServiceListTriggersProcedure:                      td.PermAutomationRead,
	pantherclawv1connect.TriggerServiceCreateEventSourceProcedure:                 td.PermAutomationEndpointsManage,
	pantherclawv1connect.TriggerServiceActivateEventSourceProcedure:               td.PermAutomationEndpointsManage,
	pantherclawv1connect.TriggerServiceRotateEventSourceSecretProcedure:           td.PermAutomationEndpointsManage,
	pantherclawv1connect.TriggerServiceDisableEventSourceProcedure:                td.PermAutomationEndpointsManage,
	pantherclawv1connect.TriggerServiceGetEventSourceProcedure:                    td.PermAutomationRead,
	pantherclawv1connect.TriggerServiceListEventSourcesProcedure:                  td.PermAutomationRead,
	pantherclawv1connect.TriggerServiceCreateAutomationDestinationProcedure:       td.PermAutomationEndpointsManage,
	pantherclawv1connect.TriggerServiceActivateAutomationDestinationProcedure:     td.PermAutomationEndpointsManage,
	pantherclawv1connect.TriggerServiceRotateAutomationDestinationSecretProcedure: td.PermAutomationEndpointsManage,
	pantherclawv1connect.TriggerServiceSetAutomationDestinationStateProcedure:     td.PermAutomationEndpointsManage,
	pantherclawv1connect.TriggerServiceGetAutomationDestinationProcedure:          td.PermAutomationRead,
	pantherclawv1connect.TriggerServiceListAutomationDestinationsProcedure:        td.PermAutomationRead,
}

func init() { maps.Copy(procedurePermissions, triggersProcedures) }

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// automationCoreProcedures are AutomationService's and ChangeService's
// procedures (G0 M11 part 2 D5, D6, D12): every automation change is
// automation.manage (human only), reads are automation.read. Change
// requests are read and declined by any authenticated caller; the use case
// checks the request's domain permission (confirming is web only).
var automationCoreProcedures = map[string]td.Permission{
	pantherclawv1connect.AutomationServiceCreateAutomationProcedure:   td.PermAutomationManage,
	pantherclawv1connect.AutomationServiceGetAutomationProcedure:      td.PermAutomationRead,
	pantherclawv1connect.AutomationServiceListAutomationsProcedure:    td.PermAutomationRead,
	pantherclawv1connect.AutomationServiceCreateDraftVersionProcedure: td.PermAutomationManage,
	pantherclawv1connect.AutomationServiceUpdateDraftVersionProcedure: td.PermAutomationManage,
	pantherclawv1connect.AutomationServiceValidateVersionProcedure:    td.PermAutomationManage,
	pantherclawv1connect.AutomationServiceGetVersionProcedure:         td.PermAutomationRead,
	pantherclawv1connect.AutomationServiceListVersionsProcedure:       td.PermAutomationRead,
	pantherclawv1connect.AutomationServiceGetVersionGraphProcedure:    td.PermAutomationRead,
	pantherclawv1connect.AutomationServiceRequestEnableProcedure:      td.PermAutomationManage,
	pantherclawv1connect.AutomationServiceNarrowRolloutProcedure:      td.PermAutomationManage,
	pantherclawv1connect.AutomationServicePauseAutomationProcedure:    td.PermAutomationManage,
	pantherclawv1connect.AutomationServiceResumeAutomationProcedure:   td.PermAutomationManage,
	pantherclawv1connect.AutomationServiceRetireAutomationProcedure:   td.PermAutomationManage,
	pantherclawv1connect.AutomationServiceRevokeAuthorityProcedure:    td.PermAutomationManage,
	pantherclawv1connect.AutomationServiceSetAutomationOwnerProcedure: td.PermAutomationManage,
	pantherclawv1connect.ChangeServiceGetChangeRequestProcedure:       td.PermAuthenticated,
	pantherclawv1connect.ChangeServiceListChangeRequestsProcedure:     td.PermAuthenticated,
	pantherclawv1connect.ChangeServiceDeclineChangeRequestProcedure:   td.PermAuthenticated,
}

func init() { maps.Copy(procedurePermissions, automationCoreProcedures) }

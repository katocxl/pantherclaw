// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m21ModelProcedures are ModelService's procedures (G0 M21 D304, D309; G16,
// F181, F304): changes need org.update, and the use cases accept a person
// only. Turning drafting on and setting the key are not here: they need a
// step-up, which only the browser settings page has. Listing drafts and
// reading usage take more than org.read (G0 M24 D95), so a Scanner's key
// reaches neither (HR-589).
var m21ModelProcedures = map[string]td.Permission{
	pantherclawv1connect.ModelServiceGetModelSettingsProcedure:     td.PermOrgRead,
	pantherclawv1connect.ModelServiceUpdateModelSettingsProcedure:  td.PermOrgUpdate,
	pantherclawv1connect.ModelServiceDisableModelDraftingProcedure: td.PermOrgUpdate,
	pantherclawv1connect.ModelServiceClearModelKeyProcedure:        td.PermOrgUpdate,
	pantherclawv1connect.ModelServiceDraftQueryProcedure:           td.PermSearchRead,
	pantherclawv1connect.ModelServiceDraftPolicyProcedure:          td.PermPolicyAuthor,
	pantherclawv1connect.ModelServiceDraftAutomationProcedure:      td.PermAutomationManage,
	pantherclawv1connect.ModelServiceGetModelDraftProcedure:        td.PermOrgRead,
	pantherclawv1connect.ModelServiceListModelDraftsProcedure:      td.PermPolicyRead,
	pantherclawv1connect.ModelServiceGetModelUsageProcedure:        td.PermAuditRead,
}

// m21ModelClasses are ModelService's plan-gate classes: turning drafting off
// and clearing the key reduce what can leave, so a lapsed plan can always do
// them.
var m21ModelClasses = map[string]entitlements.Class{
	pantherclawv1connect.ModelServiceGetModelSettingsProcedure:     entitlements.ClassRead,
	pantherclawv1connect.ModelServiceUpdateModelSettingsProcedure:  entitlements.ClassChange,
	pantherclawv1connect.ModelServiceDisableModelDraftingProcedure: entitlements.ClassSafety,
	pantherclawv1connect.ModelServiceClearModelKeyProcedure:        entitlements.ClassSafety,
	pantherclawv1connect.ModelServiceDraftQueryProcedure:           entitlements.ClassChange,
	pantherclawv1connect.ModelServiceDraftPolicyProcedure:          entitlements.ClassChange,
	pantherclawv1connect.ModelServiceDraftAutomationProcedure:      entitlements.ClassChange,
	pantherclawv1connect.ModelServiceGetModelDraftProcedure:        entitlements.ClassRead,
	pantherclawv1connect.ModelServiceListModelDraftsProcedure:      entitlements.ClassRead,
	pantherclawv1connect.ModelServiceGetModelUsageProcedure:        entitlements.ClassRead,
}

func init() {
	maps.Copy(procedurePermissions, m21ModelProcedures)
	maps.Copy(procedureClasses, m21ModelClasses)
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m38IntelProcedures are shared threat intel's procedures (G0 M38
// D1103..D1105). ContributeIndicator also needs a person and share on; the
// service checks both.
var m38IntelProcedures = map[string]td.Permission{
	pantherclawv1connect.IntelServiceGetIntelSettingsProcedure:       td.PermIntelRead,
	pantherclawv1connect.IntelServiceSetIntelSettingsProcedure:       td.PermIntelManage,
	pantherclawv1connect.IntelServiceListIntelMatchesProcedure:       td.PermIntelRead,
	pantherclawv1connect.IntelServiceContributeIndicatorProcedure:    td.PermIntelContribute,
	pantherclawv1connect.IntelServiceListIntelContributionsProcedure: td.PermIntelRead,
	pantherclawv1connect.IntelServiceExportIntelSTIXProcedure:        td.PermIntelRead,
}

// m38IntelClasses are their plan-gate classes.
var m38IntelClasses = map[string]entitlements.Class{
	pantherclawv1connect.IntelServiceGetIntelSettingsProcedure:       entitlements.ClassRead,
	pantherclawv1connect.IntelServiceSetIntelSettingsProcedure:       entitlements.ClassChange,
	pantherclawv1connect.IntelServiceListIntelMatchesProcedure:       entitlements.ClassRead,
	pantherclawv1connect.IntelServiceContributeIndicatorProcedure:    entitlements.ClassChange,
	pantherclawv1connect.IntelServiceListIntelContributionsProcedure: entitlements.ClassRead,
	pantherclawv1connect.IntelServiceExportIntelSTIXProcedure:        entitlements.ClassRead,
}

func init() {
	maps.Copy(procedurePermissions, m38IntelProcedures)
	maps.Copy(procedureClasses, m38IntelClasses)
}

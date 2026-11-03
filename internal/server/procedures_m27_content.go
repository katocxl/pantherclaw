// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m27ContentProcedures are ContentSignalService's procedures (G0 M27 D507).
// The service refuses any caller of SetMode but a person.
var m27ContentProcedures = map[string]td.Permission{
	pantherclawv1connect.ContentSignalServiceGetSettingsProcedure: td.PermContentRead,
	pantherclawv1connect.ContentSignalServiceSetModeProcedure:     td.PermContentManage,
}

// m27ContentClasses are their plan-gate classes: a lapsed org keeps seeing
// the mode and can still turn a signal off (D505, HR-652). The service checks
// the edition for the ways up.
var m27ContentClasses = map[string]entitlements.Class{
	pantherclawv1connect.ContentSignalServiceGetSettingsProcedure: entitlements.ClassRead,
	pantherclawv1connect.ContentSignalServiceSetModeProcedure:     entitlements.ClassSafety,
}

func init() {
	maps.Copy(procedurePermissions, m27ContentProcedures)
	maps.Copy(procedureClasses, m27ContentClasses)
}

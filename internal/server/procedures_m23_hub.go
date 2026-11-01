// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m23HubProcedures are HubService's procedures (G0 M23 D103). The use case
// accepts a person only; each kind of item then needs its own permission.
var m23HubProcedures = map[string]td.Permission{
	pantherclawv1connect.HubServiceInstallHubItemProcedure:  td.PermHubInstall,
	pantherclawv1connect.HubServiceListHubInstallsProcedure: td.PermHubRead,
	pantherclawv1connect.HubServiceGetHubStateProcedure:     td.PermHubRead,
}

// m23HubClasses are HubService's plan-gate classes.
var m23HubClasses = map[string]entitlements.Class{
	pantherclawv1connect.HubServiceInstallHubItemProcedure:  entitlements.ClassChange,
	pantherclawv1connect.HubServiceListHubInstallsProcedure: entitlements.ClassRead,
	pantherclawv1connect.HubServiceGetHubStateProcedure:     entitlements.ClassRead,
}

func init() {
	maps.Copy(procedurePermissions, m23HubProcedures)
	maps.Copy(procedureClasses, m23HubClasses)
}

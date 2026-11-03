// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m26SaaSProcedures are SaasDiscoveryService's procedures (G0 M26 D407).
var m26SaaSProcedures = map[string]td.Permission{
	pantherclawv1connect.SaasDiscoveryServiceImportSaasReportProcedure:  td.PermAgentManage,
	pantherclawv1connect.SaasDiscoveryServiceStartSaasScanProcedure:     td.PermAgentManage,
	pantherclawv1connect.SaasDiscoveryServiceGetSaasScanProcedure:       td.PermAgentRead,
	pantherclawv1connect.SaasDiscoveryServiceListSaasScansProcedure:     td.PermAgentRead,
	pantherclawv1connect.SaasDiscoveryServiceListSaasAgentsProcedure:    td.PermAgentRead,
	pantherclawv1connect.SaasDiscoveryServiceSetSaasAgentOwnerProcedure: td.PermAgentManage,
}

// m26SaaSClasses are its plan-gate classes.
var m26SaaSClasses = map[string]entitlements.Class{
	pantherclawv1connect.SaasDiscoveryServiceImportSaasReportProcedure:  entitlements.ClassChange,
	pantherclawv1connect.SaasDiscoveryServiceStartSaasScanProcedure:     entitlements.ClassChange,
	pantherclawv1connect.SaasDiscoveryServiceGetSaasScanProcedure:       entitlements.ClassRead,
	pantherclawv1connect.SaasDiscoveryServiceListSaasScansProcedure:     entitlements.ClassRead,
	pantherclawv1connect.SaasDiscoveryServiceListSaasAgentsProcedure:    entitlements.ClassRead,
	pantherclawv1connect.SaasDiscoveryServiceSetSaasAgentOwnerProcedure: entitlements.ClassChange,
}

func init() {
	maps.Copy(procedurePermissions, m26SaaSProcedures)
	maps.Copy(procedureClasses, m26SaaSClasses)
}

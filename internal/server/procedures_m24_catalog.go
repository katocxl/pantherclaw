// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m24CatalogProcedures are McpCatalogService's procedures (G0 M24 D222). The
// mode and a revoke are for a person with a step-up: the service refuses any
// other caller.
var m24CatalogProcedures = map[string]td.Permission{
	pantherclawv1connect.McpCatalogServiceProposeServerProcedure:       td.PermCatalogManage,
	pantherclawv1connect.McpCatalogServiceApproveServerProcedure:       td.PermCatalogManage,
	pantherclawv1connect.McpCatalogServiceDenyServerProcedure:          td.PermCatalogManage,
	pantherclawv1connect.McpCatalogServiceListServersProcedure:         td.PermCatalogRead,
	pantherclawv1connect.McpCatalogServiceGetServerProcedure:           td.PermCatalogRead,
	pantherclawv1connect.McpCatalogServiceGetCatalogSettingsProcedure:  td.PermCatalogRead,
	pantherclawv1connect.McpCatalogServicePreviewCatalogModeProcedure:  td.PermCatalogRead,
	pantherclawv1connect.McpCatalogServiceSetCatalogModeProcedure:      td.PermCatalogManage,
	pantherclawv1connect.McpCatalogServicePreviewServerRevokeProcedure: td.PermCatalogRead,
	pantherclawv1connect.McpCatalogServiceRevokeServerProcedure:        td.PermCatalogManage,
}

func init() { maps.Copy(procedurePermissions, m24CatalogProcedures) }

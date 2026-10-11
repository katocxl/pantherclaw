// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// connectorProcedures are the procedures of the connector runtime (G0 M9
// track C). TestProcedurePermissionsMatchProtos checks the merged map.
var connectorProcedures = map[string]td.Permission{
	pantherclawv1connect.GatewayServiceReportConnectorStateProcedure: "gateway.observe",
}

func init() { maps.Copy(procedurePermissions, connectorProcedures) }

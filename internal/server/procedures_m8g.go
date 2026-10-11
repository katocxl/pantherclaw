// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m8gProcedures are the procedures of M8 track G (G0 M8): the gateway
// reporting GitHub facts as a connection's provider.
// TestProcedurePermissionsMatchProtos checks the merged map.
var m8gProcedures = map[string]td.Permission{
	pantherclawv1connect.GatewayServiceReportFactsProcedure: td.PermGatewayFactsReport,
}

func init() { maps.Copy(procedurePermissions, m8gProcedures) }

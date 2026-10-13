// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m8cProcedures are G0 M8 track C's procedures: connection capability
// declarations, tests and health (F346, F354, F358) and the gateway's tool
// observations (HR-200). They live beside procedurePermissions to keep the
// shared map small; TestProcedurePermissionsMatchProtos checks the merged
// map.
var m8cProcedures = map[string]td.Permission{
	pantherclawv1connect.ConnectionServiceGetConnectionCapabilitiesProcedure: "connection.read",
	pantherclawv1connect.ConnectionServiceTestConnectionProcedure:            "connection.test",
	pantherclawv1connect.ConnectionServiceGetConnectionHealthProcedure:       "connection.read",
	pantherclawv1connect.AuthorityServiceRecordToolObservationProcedure:      "gateway.observe",
	pantherclawv1connect.GatewayServiceMintTestActionTokensProcedure:         "gateway.verify",
}

func init() { maps.Copy(procedurePermissions, m8cProcedures) }

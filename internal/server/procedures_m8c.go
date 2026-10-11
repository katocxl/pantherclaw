// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m8cProcedures are G0 M8 track C's procedures: connection capability
// declarations (F346). They live beside procedurePermissions to keep the
// shared map small; TestProcedurePermissionsMatchProtos checks the merged
// map.
var m8cProcedures = map[string]td.Permission{
	pantherclawv1connect.ConnectionServiceGetConnectionCapabilitiesProcedure: "connection.read",
}

func init() { maps.Copy(procedurePermissions, m8cProcedures) }

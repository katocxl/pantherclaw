// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m24SupplyProcedures are SupplyChainService's procedures (G0 M24 D212).
var m24SupplyProcedures = map[string]td.Permission{
	pantherclawv1connect.SupplyChainServiceListSupplyChainFlagsProcedure: td.PermConnectionRead,
}

func init() { maps.Copy(procedurePermissions, m24SupplyProcedures) }

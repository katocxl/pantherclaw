// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// uiEntitlementProcedures are EntitlementService's procedures (G0 UI D9):
// reading the org's plan. Nothing in the API changes a plan (HR-354).
var uiEntitlementProcedures = map[string]td.Permission{
	pantherclawv1connect.EntitlementServiceGetEntitlementsProcedure: td.PermEntitlementsRead,
}

func init() { maps.Copy(procedurePermissions, uiEntitlementProcedures) }

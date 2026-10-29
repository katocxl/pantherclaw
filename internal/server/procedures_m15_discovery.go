// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m15DiscoveryProcedures are the F352 discovery inventory procedures (G0
// M15 D23, D6): reading a connection's inventory, dismissing an item and
// drafting an unsigned package from items.
var m15DiscoveryProcedures = map[string]td.Permission{
	pantherclawv1connect.ConnectionServiceListConnectionInventoryProcedure:   td.PermConnectionRead,
	pantherclawv1connect.ConnectionServiceDismissInventoryItemProcedure:      td.PermConnectionManage,
	pantherclawv1connect.ConnectionServiceDraftPackageFromInventoryProcedure: td.PermPackageImport,
}

func init() { maps.Copy(procedurePermissions, m15DiscoveryProcedures) }

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The M34 discovery stream's wiring (G0 M34 D997): daily scans of SaaS and
// cloud agent runtime connections.

var m34DiscoveryProcedures = map[string]td.Permission{
	pantherclawv1connect.SaasDiscoveryServiceSetSaaSScanScheduleProcedure: td.PermAgentManage,
}

// Setting a schedule makes the server send the connection's credential to
// work every day as the person who set it, as starting a scan does: a
// change.
var m34DiscoveryClasses = map[string]entitlements.Class{
	pantherclawv1connect.SaasDiscoveryServiceSetSaaSScanScheduleProcedure: entitlements.ClassChange,
}

func init() {
	maps.Copy(procedurePermissions, m34DiscoveryProcedures)
	maps.Copy(procedureClasses, m34DiscoveryClasses)
}

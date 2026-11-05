// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m36OTelProcedures are OTLPDestinationService's procedures (G0 M36
// D1061). Changes need otlp.manage, which only a person holds; reads need
// otlp.read. Activation over the API is always refused (STEP_UP_REQUIRED).
var m36OTelProcedures = map[string]td.Permission{
	pantherclawv1connect.OTLPDestinationServiceCreateOTLPDestinationProcedure:   td.PermOTLPManage,
	pantherclawv1connect.OTLPDestinationServiceActivateOTLPDestinationProcedure: td.PermOTLPManage,
	pantherclawv1connect.OTLPDestinationServiceDisableOTLPDestinationProcedure:  td.PermOTLPManage,
	pantherclawv1connect.OTLPDestinationServiceListOTLPDestinationsProcedure:    td.PermOTLPRead,
	pantherclawv1connect.OTLPDestinationServiceGetOTLPDestinationProcedure:      td.PermOTLPRead,
	pantherclawv1connect.OTLPDestinationServiceTestOTLPDestinationProcedure:     td.PermOTLPManage,
}

// m36OTelClasses are their plan-gate classes: a lapsed org keeps reading
// and can still disable a destination, which only stops sending; creating,
// activating and testing send data out.
var m36OTelClasses = map[string]entitlements.Class{
	pantherclawv1connect.OTLPDestinationServiceCreateOTLPDestinationProcedure:   entitlements.ClassChange,
	pantherclawv1connect.OTLPDestinationServiceActivateOTLPDestinationProcedure: entitlements.ClassChange,
	pantherclawv1connect.OTLPDestinationServiceDisableOTLPDestinationProcedure:  entitlements.ClassSafety,
	pantherclawv1connect.OTLPDestinationServiceListOTLPDestinationsProcedure:    entitlements.ClassRead,
	pantherclawv1connect.OTLPDestinationServiceGetOTLPDestinationProcedure:      entitlements.ClassRead,
	pantherclawv1connect.OTLPDestinationServiceTestOTLPDestinationProcedure:     entitlements.ClassChange,
}

func init() {
	maps.Copy(procedurePermissions, m36OTelProcedures)
	maps.Copy(procedureClasses, m36OTelClasses)
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m28ThreatMapProcedures are ThreatMapService's procedures (G0 M28 D721,
// D722). Every one needs threatmap.read; the use case then checks the
// agent and environment filters against the caller's scope, and the
// edition and credential (D723).
var m28ThreatMapProcedures = map[string]td.Permission{
	pantherclawv1connect.ThreatMapServiceListThreatFrameworksProcedure: td.PermThreatMapRead,
	pantherclawv1connect.ThreatMapServiceGetThreatMatrixProcedure:      td.PermThreatMapRead,
	pantherclawv1connect.ThreatMapServiceGetThreatTechniqueProcedure:   td.PermThreatMapRead,
	pantherclawv1connect.ThreatMapServiceListThreatGapsProcedure:       td.PermThreatMapRead,
	pantherclawv1connect.ThreatMapServiceExportNavigatorLayerProcedure: td.PermThreatMapRead,
	pantherclawv1connect.ThreatMapServiceGetThreatMapHistoryProcedure:  td.PermThreatMapRead,
}

// m28ThreatMapClasses are their plan-gate classes: all reads (D721). The
// use case checks the edition, never an interceptor.
var m28ThreatMapClasses = map[string]entitlements.Class{
	pantherclawv1connect.ThreatMapServiceListThreatFrameworksProcedure: entitlements.ClassRead,
	pantherclawv1connect.ThreatMapServiceGetThreatMatrixProcedure:      entitlements.ClassRead,
	pantherclawv1connect.ThreatMapServiceGetThreatTechniqueProcedure:   entitlements.ClassRead,
	pantherclawv1connect.ThreatMapServiceListThreatGapsProcedure:       entitlements.ClassRead,
	pantherclawv1connect.ThreatMapServiceExportNavigatorLayerProcedure: entitlements.ClassRead,
	pantherclawv1connect.ThreatMapServiceGetThreatMapHistoryProcedure:  entitlements.ClassRead,
}

func init() {
	maps.Copy(procedurePermissions, m28ThreatMapProcedures)
	maps.Copy(procedureClasses, m28ThreatMapClasses)
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m15GatewayProcedures are the M15 gateway procedures (G0 M15 D6, D10,
// D12): status reports and the gateway's shared MCP state.
var m15GatewayProcedures = map[string]td.Permission{
	pantherclawv1connect.GatewayServiceReportStatusProcedure:   "gateway.observe",
	pantherclawv1connect.GatewayServicePutMCPStateProcedure:    "gateway.sync",
	pantherclawv1connect.GatewayServiceGetMCPStateProcedure:    "gateway.sync",
	pantherclawv1connect.GatewayServiceDeleteMCPStateProcedure: "gateway.sync",
}

func init() { maps.Copy(procedurePermissions, m15GatewayProcedures) }

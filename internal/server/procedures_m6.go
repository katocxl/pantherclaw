// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m6Procedures are the M6 procedures (G0 M6): gateway administration and
// the gateway-facing GatewayService, connections and sealed credentials,
// and the kill switch's status. They live beside procedurePermissions to
// keep the shared map small; TestProcedurePermissionsMatchProtos checks the
// merged map.
var m6Procedures = map[string]td.Permission{
	pantherclawv1connect.GatewayAdminServiceCreateGatewayProcedure:                "gateway.manage",
	pantherclawv1connect.GatewayAdminServiceCreateGatewayEnrollmentTokenProcedure: "gateway.manage",
	pantherclawv1connect.GatewayAdminServiceListGatewaysProcedure:                 "gateway.read",
	pantherclawv1connect.GatewayAdminServiceGetGatewayProcedure:                   "gateway.read",
	pantherclawv1connect.GatewayAdminServiceRevokeGatewayProcedure:                "gateway.manage",
	pantherclawv1connect.GatewayAdminServiceRevokeGatewayCertificateProcedure:     "gateway.manage",
	pantherclawv1connect.GatewayAdminServiceListApproverKeysProcedure:             "gateway.read",
	pantherclawv1connect.GatewayServiceEnrollProcedure:                            "gateway.enroll",
	pantherclawv1connect.GatewayServiceRenewCertificateProcedure:                  "gateway.sync",
	pantherclawv1connect.GatewayServiceRegisterBrokerKeyProcedure:                 "gateway.sync",
	pantherclawv1connect.GatewayServiceGetConfigurationProcedure:                  "gateway.sync",
	pantherclawv1connect.GatewayServiceWatchContainmentProcedure:                  "gateway.sync",
	pantherclawv1connect.GatewayServiceReportCircuitProcedure:                     "gateway.observe",
	pantherclawv1connect.GatewayServiceReportDriftProcedure:                       "gateway.observe",
	pantherclawv1connect.ConnectionServiceCreateConnectionProcedure:               "connection.manage",
	pantherclawv1connect.ConnectionServiceGetConnectionProcedure:                  "connection.read",
	pantherclawv1connect.ConnectionServiceListConnectionsProcedure:                "connection.read",
	pantherclawv1connect.ConnectionServiceUpdateConnectionProcedure:               "connection.manage",
	pantherclawv1connect.ConnectionServiceSetRouteModeProcedure:                   "connection.manage",
	pantherclawv1connect.ConnectionServiceQuarantineConnectionProcedure:           "connection.manage",
	pantherclawv1connect.ConnectionServiceRestoreConnectionProcedure:              "connection.manage",
	pantherclawv1connect.ConnectionServiceRetireConnectionProcedure:               "connection.manage",
	pantherclawv1connect.ConnectionServiceGetSealingKeyProcedure:                  "credential.seal",
	pantherclawv1connect.ConnectionServicePutCredentialProcedure:                  "credential.seal",
	pantherclawv1connect.ConnectionServiceListCredentialsProcedure:                "connection.read",
	pantherclawv1connect.ConnectionServiceRevokeCredentialProcedure:               "connection.manage",
	pantherclawv1connect.ContainmentServiceGetKillSwitchProcedure:                 "containment.read",
}

func init() { maps.Copy(procedurePermissions, m6Procedures) }

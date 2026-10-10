// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m7aProcedures are the procedures of M7 track A (G0 M7): the
// gateway-facing verification leases and reports, the evidence explorer
// and reconciliation. TestProcedurePermissionsMatchProtos checks the merged
// map.
var m7aProcedures = map[string]td.Permission{
	pantherclawv1connect.GatewayServiceClaimVerificationsProcedure:         "gateway.verify",
	pantherclawv1connect.GatewayServiceReportObservationProcedure:          "gateway.verify",
	pantherclawv1connect.TransactionServiceListTransactionsProcedure:       "evidence.read",
	pantherclawv1connect.TransactionServiceGetTransactionEvidenceProcedure: "evidence.read",
	pantherclawv1connect.ReconciliationServiceListReconciliationsProcedure: "evidence.read",
	pantherclawv1connect.ReconciliationServiceGetReconciliationProcedure:   "evidence.read",
	pantherclawv1connect.ReconciliationServiceResolveOccurredProcedure:     "transaction.reconcile",
	pantherclawv1connect.ReconciliationServiceRequestVerificationProcedure: "transaction.reconcile",
	pantherclawv1connect.ReconciliationServiceLinkTransactionProcedure:     "transaction.reconcile",
}

func init() { maps.Copy(procedurePermissions, m7aProcedures) }

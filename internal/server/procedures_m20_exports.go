// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// exportProcedures are ExportDestinationService's procedures (G0 M20 D252):
// the SIEM destination permissions. Changes need siem.manage (a person,
// checked again by the use cases with the Business edition); reads need
// siem.read.
var exportProcedures = map[string]td.Permission{
	pantherclawv1connect.ExportDestinationServiceCreateExportDestinationProcedure:            td.PermSIEMManage,
	pantherclawv1connect.ExportDestinationServiceGetExportDestinationProcedure:               td.PermSIEMRead,
	pantherclawv1connect.ExportDestinationServiceListExportDestinationsProcedure:             td.PermSIEMRead,
	pantherclawv1connect.ExportDestinationServiceSetExportDestinationStateProcedure:          td.PermSIEMManage,
	pantherclawv1connect.ExportDestinationServiceReplaceExportDestinationCredentialProcedure: td.PermSIEMManage,
	pantherclawv1connect.ExportDestinationServicePushExportArtifactProcedure:                 td.PermSIEMManage,
	pantherclawv1connect.ExportDestinationServiceGetExportReceiptProcedure:                   td.PermSIEMRead,
	pantherclawv1connect.ExportDestinationServiceListExportReceiptsProcedure:                 td.PermSIEMRead,
}

// exportClasses are their plan-gate classes (HR-356), as SIEM's.
var exportClasses = map[string]entitlements.Class{
	pantherclawv1connect.ExportDestinationServiceCreateExportDestinationProcedure:            entitlements.ClassChange,
	pantherclawv1connect.ExportDestinationServiceGetExportDestinationProcedure:               entitlements.ClassRead,
	pantherclawv1connect.ExportDestinationServiceListExportDestinationsProcedure:             entitlements.ClassRead,
	pantherclawv1connect.ExportDestinationServiceSetExportDestinationStateProcedure:          entitlements.ClassChange,
	pantherclawv1connect.ExportDestinationServiceReplaceExportDestinationCredentialProcedure: entitlements.ClassChange,
	pantherclawv1connect.ExportDestinationServicePushExportArtifactProcedure:                 entitlements.ClassChange,
	pantherclawv1connect.ExportDestinationServiceGetExportReceiptProcedure:                   entitlements.ClassRead,
	pantherclawv1connect.ExportDestinationServiceListExportReceiptsProcedure:                 entitlements.ClassRead,
}

func init() {
	maps.Copy(procedurePermissions, exportProcedures)
	maps.Copy(procedureClasses, exportClasses)
}

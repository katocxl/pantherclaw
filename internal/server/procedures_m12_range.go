// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// rangeProcedures are RangeService's procedures (G0 M12, HR-224):
// redteam.run over the range agent, reads are redteam.read, and exporting
// the assurance report is evidence.export (human only).
var rangeProcedures = map[string]td.Permission{
	pantherclawv1connect.RangeServiceStartRangeProcedure:            td.PermRedteamRun,
	pantherclawv1connect.RangeServiceRecordResultProcedure:          td.PermRedteamRun,
	pantherclawv1connect.RangeServiceFinishRangeProcedure:           td.PermRedteamRun,
	pantherclawv1connect.RangeServiceGetRangeProcedure:              td.PermRedteamRead,
	pantherclawv1connect.RangeServiceListRangesProcedure:            td.PermRedteamRead,
	pantherclawv1connect.RangeServiceExportAssuranceReportProcedure: td.PermEvidenceExport,
}

func init() { maps.Copy(procedurePermissions, rangeProcedures) }

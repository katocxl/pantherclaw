// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// caseProcedures are CaseService's and InvestigationService's procedures
// (G0 M10 D19, D20): changes need case.manage (a person only), reads
// case.read, and the run investigation views evidence.read; the use cases
// check the scope over the case's agents, and the export also needs
// evidence.export (HR-247).
var caseProcedures = map[string]td.Permission{
	pantherclawv1connect.CaseServiceOpenCaseProcedure:                     td.PermCaseManage,
	pantherclawv1connect.CaseServiceAppendCaseEntryProcedure:              td.PermCaseManage,
	pantherclawv1connect.CaseServiceGetCaseProcedure:                      td.PermCaseRead,
	pantherclawv1connect.CaseServiceListCasesProcedure:                    td.PermCaseRead,
	pantherclawv1connect.CaseServiceGetCaseLensProcedure:                  td.PermCaseRead,
	pantherclawv1connect.CaseServiceExportCaseProcedure:                   td.PermCaseRead,
	pantherclawv1connect.InvestigationServiceWhatHappenedProcedure:        td.PermEvidenceRead,
	pantherclawv1connect.InvestigationServiceGetRunTimelineProcedure:      td.PermEvidenceRead,
	pantherclawv1connect.InvestigationServiceGetPrecedingContextProcedure: td.PermEvidenceRead,
	pantherclawv1connect.InvestigationServiceCompareRunProcedure:          td.PermEvidenceRead,
}

func init() { maps.Copy(procedurePermissions, caseProcedures) }

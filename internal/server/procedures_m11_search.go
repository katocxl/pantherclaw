// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m11SearchProcedures are SearchService's G0 M11 part 2 procedures (D45,
// D46, D48). Find, Interpret and Ask need search.read; opening a case from
// results needs case.manage and exporting results evidence.export, and each
// use case also checks search.read and every row's own read permission.
var m11SearchProcedures = map[string]td.Permission{
	pantherclawv1connect.SearchServiceFindProcedure:                td.PermSearchRead,
	pantherclawv1connect.SearchServiceInterpretProcedure:           td.PermSearchRead,
	pantherclawv1connect.SearchServiceAskProcedure:                 td.PermSearchRead,
	pantherclawv1connect.SearchServiceOpenCaseFromResultsProcedure: td.PermCaseManage,
	pantherclawv1connect.SearchServiceExportResultsProcedure:       td.PermEvidenceExport,
}

func init() { maps.Copy(procedurePermissions, m11SearchProcedures) }

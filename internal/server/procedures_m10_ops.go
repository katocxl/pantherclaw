// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m10OpsProcedures are OperationsService's and SearchService's procedures
// (G0 M10 D33, D34): operations.read and search.read; each use case then
// filters by the caller's scope for the rows' own read permissions (D8).
var m10OpsProcedures = map[string]td.Permission{
	pantherclawv1connect.OperationsServiceGetWorkQueueProcedure:      td.PermOperationsRead,
	pantherclawv1connect.OperationsServiceGetSummaryProcedure:        td.PermOperationsRead,
	pantherclawv1connect.OperationsServiceGetEvidenceStatusProcedure: td.PermOperationsRead,
	pantherclawv1connect.SearchServiceSearchProcedure:                td.PermSearchRead,
	pantherclawv1connect.SearchServiceListBuiltinQueriesProcedure:    td.PermSearchRead,
	pantherclawv1connect.SearchServiceRunBuiltinQueryProcedure:       td.PermSearchRead,
	pantherclawv1connect.SearchServiceSaveQueryProcedure:             td.PermSearchRead,
	pantherclawv1connect.SearchServiceUpdateSavedQueryProcedure:      td.PermSearchRead,
	pantherclawv1connect.SearchServiceDeleteSavedQueryProcedure:      td.PermSearchRead,
	pantherclawv1connect.SearchServiceGetSavedQueryProcedure:         td.PermSearchRead,
	pantherclawv1connect.SearchServiceListSavedQueriesProcedure:      td.PermSearchRead,
	pantherclawv1connect.SearchServiceRunSavedQueryProcedure:         td.PermSearchRead,
}

func init() { maps.Copy(procedurePermissions, m10OpsProcedures) }

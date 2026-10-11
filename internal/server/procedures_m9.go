// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// coverageProcedures are CoverageService's procedures (G0 M9 track A).
// Reads check coverage.read over each agent, reassessing coverage.reassess,
// and exclusions coverage.manage, which is human only.
var coverageProcedures = map[string]td.Permission{
	pantherclawv1connect.CoverageServiceGetCoverageProcedure:          td.PermCoverageRead,
	pantherclawv1connect.CoverageServiceListCoverageProcedure:         td.PermCoverageRead,
	pantherclawv1connect.CoverageServiceListRoutesProcedure:           td.PermCoverageRead,
	pantherclawv1connect.CoverageServiceGetClosureProcedure:           td.PermCoverageRead,
	pantherclawv1connect.CoverageServiceListClosuresProcedure:         td.PermCoverageRead,
	pantherclawv1connect.CoverageServiceGetFreshnessContractProcedure: td.PermCoverageRead,
	pantherclawv1connect.CoverageServiceReassessProcedure:             td.PermCoverageReassess,
	pantherclawv1connect.CoverageServiceCreateExclusionProcedure:      td.PermCoverageManage,
	pantherclawv1connect.CoverageServiceRevokeExclusionProcedure:      td.PermCoverageManage,
	pantherclawv1connect.CoverageServiceListExclusionsProcedure:       td.PermCoverageRead,
	pantherclawv1connect.CoverageServiceGetAccessDisclosureProcedure:  td.PermCoverageRead,
}

func init() { maps.Copy(procedurePermissions, coverageProcedures) }

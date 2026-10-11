// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// coverageProcedures are CoverageService's procedures (G0 M9 track A).
// Reads check coverage.read over each agent; reassessing needs
// coverage.manage, which is human only.
var coverageProcedures = map[string]td.Permission{
	pantherclawv1connect.CoverageServiceGetCoverageProcedure:          td.PermCoverageRead,
	pantherclawv1connect.CoverageServiceListCoverageProcedure:         td.PermCoverageRead,
	pantherclawv1connect.CoverageServiceListCoverageRoutesProcedure:   td.PermCoverageRead,
	pantherclawv1connect.CoverageServiceGetFreshnessContractProcedure: td.PermCoverageRead,
	pantherclawv1connect.CoverageServiceReassessCoverageProcedure:     td.PermCoverageManage,
}

func init() { maps.Copy(procedurePermissions, coverageProcedures) }

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// rows26CoverageProcedures are the coverage reads added for the partly
// built v1.0 rows (rows26 S3): the coverage graph (F277) reads with
// coverage.read over the agent, on Team and above.
var rows26CoverageProcedures = map[string]td.Permission{
	pantherclawv1connect.CoverageServiceGetCoverageGraphProcedure: td.PermCoverageRead,
}

func init() { maps.Copy(procedurePermissions, rows26CoverageProcedures) }

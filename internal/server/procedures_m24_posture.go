// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m24PostureProcedures are PostureQueueService's procedures (G0 M24 D200):
// reading needs posture.read somewhere and the use case resolves the
// viewer's scope before it ranks anything.
var m24PostureProcedures = map[string]td.Permission{
	pantherclawv1connect.PostureQueueServiceListRankedFindingsProcedure: td.PermPostureRead,
	pantherclawv1connect.PostureQueueServiceGetPostureTrendsProcedure:   td.PermPostureRead,
}

func init() { maps.Copy(procedurePermissions, m24PostureProcedures) }

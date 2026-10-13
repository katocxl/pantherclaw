// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m8pProcedures are G0 M8 track P's procedures: change windows (HR-207).
// They live beside procedurePermissions to keep the shared map small;
// TestProcedurePermissionsMatchProtos checks the merged map.
var m8pProcedures = map[string]td.Permission{
	pantherclawv1connect.ChangeWindowServiceCreateChangeWindowProcedure: "release.window.manage",
	pantherclawv1connect.ChangeWindowServiceListChangeWindowsProcedure:  "release.window.manage",
	pantherclawv1connect.ChangeWindowServiceRetireChangeWindowProcedure: "release.window.manage",
	pantherclawv1connect.ChangeWindowServiceGetActiveWindowsProcedure:   "release.window.manage",
}

func init() { maps.Copy(procedurePermissions, m8pProcedures) }

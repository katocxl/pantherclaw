// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// sandboxProcedures are SandboxService's procedures (G0 M9 track B):
// sandbox.run over the session's agent; reads are coverage reads.
var sandboxProcedures = map[string]td.Permission{
	pantherclawv1connect.SandboxServiceStartSessionProcedure:       td.PermSandboxRun,
	pantherclawv1connect.SandboxServiceSubmitProbeReportProcedure:  td.PermSandboxRun,
	pantherclawv1connect.SandboxServiceSubmitCanaryReportProcedure: td.PermSandboxRun,
	pantherclawv1connect.SandboxServiceEndSessionProcedure:         td.PermSandboxRun,
	pantherclawv1connect.SandboxServiceReportRoutesProcedure:       td.PermSandboxRun,
	pantherclawv1connect.SandboxServiceGetSessionProcedure:         td.PermCoverageRead,
	pantherclawv1connect.SandboxServiceListSessionsProcedure:       td.PermCoverageRead,
}

func init() { maps.Copy(procedurePermissions, sandboxProcedures) }

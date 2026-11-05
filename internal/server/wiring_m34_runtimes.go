// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The M34 core stream's wiring (G0 M34 D991, D992): a connection's runtime
// target, and runs of instances in cloud agent runtimes.

var m34RuntimeProcedures = map[string]td.Permission{
	pantherclawv1connect.ConnectionServiceSetConnectionRuntimeTargetProcedure:   td.PermConnectionManage,
	pantherclawv1connect.ConnectionServiceClearConnectionRuntimeTargetProcedure: td.PermConnectionManage,
	// PAP/1 only, as KubernetesService (D970c): no class.
	pantherclawv1connect.RuntimeServiceStartRuntimeRunProcedure: td.PermWorkloadRun,
}

// Setting a runtime target adds a way for a runtime's gateway to be decided
// through the connection (a change); clearing one removes it (safety), as
// for a gateway's Kubernetes binding.
var m34RuntimeClasses = map[string]entitlements.Class{
	pantherclawv1connect.ConnectionServiceSetConnectionRuntimeTargetProcedure:   entitlements.ClassChange,
	pantherclawv1connect.ConnectionServiceClearConnectionRuntimeTargetProcedure: entitlements.ClassSafety,
}

func init() {
	maps.Copy(procedurePermissions, m34RuntimeProcedures)
	maps.Copy(procedureClasses, m34RuntimeClasses)
}

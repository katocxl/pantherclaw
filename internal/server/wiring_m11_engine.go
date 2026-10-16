// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// registerAutomationsEngine serves ExecutionService and
// AutomationLaunchService (G0 M11 part 2 D26, D28, D29). Phase A: the
// contracts only; every procedure answers Unimplemented until the engine
// is wired.
func registerAutomationsEngine(rs *connect.Server, _ apiDeps) {
	pantherclawv1connect.RegisterExecutionServiceHandler(rs, pantherclawv1connect.UnimplementedExecutionServiceHandler{})
	pantherclawv1connect.RegisterAutomationLaunchServiceHandler(rs,
		pantherclawv1connect.UnimplementedAutomationLaunchServiceHandler{})
}

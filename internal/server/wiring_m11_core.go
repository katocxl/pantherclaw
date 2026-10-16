// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// registerAutomationsCore serves AutomationService and ChangeService (G0
// M11 part 2 D5, D6). Phase A: the contracts only; every procedure answers
// Unimplemented until the automations app is wired.
func registerAutomationsCore(rs *connect.Server, _ apiDeps) {
	pantherclawv1connect.RegisterAutomationServiceHandler(rs, pantherclawv1connect.UnimplementedAutomationServiceHandler{})
	pantherclawv1connect.RegisterChangeServiceHandler(rs, pantherclawv1connect.UnimplementedChangeServiceHandler{})
}

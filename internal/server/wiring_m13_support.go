// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// The M13 support stream's wiring (G0 M13 D32, D33, D38): customer-approved
// support access and break-glass.

type supportAccessHandler struct {
	pantherclawv1connect.UnimplementedSupportAccessServiceHandler
}

type breakGlassHandler struct {
	pantherclawv1connect.UnimplementedBreakGlassServiceHandler
}

// registerSupport serves SupportAccessService and BreakGlassService.
func registerSupport(rs *connect.Server, _ apiDeps) {
	pantherclawv1connect.RegisterSupportAccessServiceHandler(rs, supportAccessHandler{})
	pantherclawv1connect.RegisterBreakGlassServiceHandler(rs, breakGlassHandler{})
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// Per-org entitlements (G0 UI D9). Phase A serves EntitlementService's
// contract only; every call answers Unimplemented until the per-org plan
// store lands.

// entitlementService serves EntitlementService.
type entitlementService struct {
	pantherclawv1connect.UnimplementedEntitlementServiceHandler
}

// registerUIEntitlements serves EntitlementService.
func registerUIEntitlements(rs *connect.Server, _ apiDeps) {
	pantherclawv1connect.RegisterEntitlementServiceHandler(rs, entitlementService{})
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"
)

// Hosted accounts and self-serve organizations (G0 UI D8). Phase A:
// TenancyService.CreateOrg and ListMyOrgs answer Unimplemented through the
// tenancy handler's embedded defaults; this registers the UI phase's other
// core services.

// registerUITenancy serves the UI phase's core services.
func registerUITenancy(rs *connect.Server, d apiDeps) {
	registerUIEntitlements(rs, d)
	registerUIOnboarding(rs, d)
}

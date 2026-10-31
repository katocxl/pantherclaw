// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/connections/adapters/connectionsrpc"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// registerM22Rotation adds credential rotation to the public API and its
// activation page to the browser (G0 M22 D5, F831). The page is the only
// place a rotation is activated or rolled back: that needs a step-up.
func registerM22Rotation(rs *connect.Server, d apiDeps) {
	if d.m6 == nil {
		return
	}
	pantherclawv1connect.RegisterCredentialRotationServiceHandler(rs, connectionsrpc.NewRotations(d.m6.credentials))
	if d.web != nil {
		d.web.WithCredentialRotations(d.m6.credentials)
	}
}

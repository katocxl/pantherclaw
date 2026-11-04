// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/ownedaccounts/adapters/ownedrpc"
	ownedapp "github.com/katocxl/pantherclaw/internal/ownedaccounts/app"
)

// registerM30 serves OwnedAccountService (G0 M30 D933) and holds every
// addition to the owned list behind the Gate. The procedure permissions are
// in procedures_m30.go.
func registerM30(rs *connect.Server, d apiDeps) {
	svc := &ownedapp.Service{Pool: d.pool}
	svc.RegisterProtect(d.m11protect.gate)
	pantherclawv1connect.RegisterOwnedAccountServiceHandler(rs, ownedrpc.New(svc))
}

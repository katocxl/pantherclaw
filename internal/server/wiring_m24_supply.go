// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	"github.com/katocxl/pantherclaw/internal/supplychain/adapters/pgflags"
	"github.com/katocxl/pantherclaw/internal/supplychain/adapters/supplychainrpc"
	scapp "github.com/katocxl/pantherclaw/internal/supplychain/app"
)

// The queue reads open flags (G0 M24 D204, D212).
func init() {
	postureSourceFactories = append(postureSourceFactories, func(pool *db.Pool, _ exapp.Entitlements) ports.Source {
		return &pgflags.Source{Pool: pool}
	})
}

// registerM24Supply serves SupplyChainService on the public API, as pc_app.
func registerM24Supply(rs *connect.Server, d apiDeps) {
	pantherclawv1connect.RegisterSupplyChainServiceHandler(rs, supplychainrpc.New(&scapp.Service{Pool: d.pool}))
}

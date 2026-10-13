// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/releases/adapters/releasesrpc"
	rapp "github.com/katocxl/pantherclaw/internal/releases/app"
)

// registerReleases serves ChangeWindowService on the public API (G0 M8,
// HR-207), as pc_app.
func registerReleases(rs *connect.Server, pool *db.Pool) {
	pantherclawv1connect.RegisterChangeWindowServiceHandler(rs, releasesrpc.New(&rapp.Service{Pool: pool}))
}

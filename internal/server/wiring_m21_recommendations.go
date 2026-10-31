// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/recommendations/adapters/recommendationsrpc"
	recapp "github.com/katocxl/pantherclaw/internal/recommendations/app"
)

// registerRecommendations serves RecommendationService on the public API
// (G0 M21 D302), as pc_app.
func registerRecommendations(rs *connect.Server, d apiDeps) {
	pantherclawv1connect.RegisterRecommendationServiceHandler(rs,
		recommendationsrpc.New(&recapp.Service{Pool: d.pool, Ents: exposureEnts(d.billing)}))
}

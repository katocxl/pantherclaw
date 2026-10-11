// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/coverage/adapters/coveragerpc"
	coverage "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// registerCoverage serves CoverageService on the public API (G0 M9 track
// A), as pc_app.
func registerCoverage(rs *connect.Server, d apiDeps) {
	pantherclawv1connect.RegisterCoverageServiceHandler(rs, coveragerpc.New(d.freshness))
}

// freshnessOf returns the configured freshness contract; Validate has
// checked it, so an error only falls back to the defaults.
func freshnessOf(cfg *Config) coverage.Freshness {
	f, err := cfg.freshness()
	if err != nil {
		f, _ = coverage.NewFreshness(0, 0)
	}
	return f
}

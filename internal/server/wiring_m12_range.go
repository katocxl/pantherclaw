// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/ranges/adapters/pgranges"
	"github.com/katocxl/pantherclaw/internal/ranges/adapters/rangerpc"
	rangeapp "github.com/katocxl/pantherclaw/internal/ranges/app"
)

// registerRanges serves RangeService on the public API (G0 M12 W5), as
// pc_app. Editions come from the licence; without one the server is
// Community.
func registerRanges(rs *connect.Server, d apiDeps) {
	svc := &rangeapp.Service{Store: pgranges.Store{Pool: d.pool}}
	if d.billing != nil {
		svc.Editions = d.billing
	}
	pantherclawv1connect.RegisterRangeServiceHandler(rs, rangerpc.New(svc))
}

// registerRangeJobs adds the range's background jobs (the abandon sweep)
// and returns their schedule.
func registerRangeJobs(reg *jobs.Registry, pool *db.Pool, log *slog.Logger) ([]*river.PeriodicJob, error) {
	return pgranges.RegisterAbandon(reg, pool, log)
}

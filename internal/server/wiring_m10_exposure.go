// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/exposure/adapters/exposurerpc"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/exposure/recompute"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/posture/adapters/posturerpc"
	poapp "github.com/katocxl/pantherclaw/internal/posture/app"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	sgapp "github.com/katocxl/pantherclaw/internal/suggestions/app"
)

// exposureEnts is the licence as the exposure services read it; without
// one (nil) every use case fails closed with EDITION_REQUIRED.
func exposureEnts(b *billing.Service) exapp.Entitlements {
	if b == nil {
		return nil
	}
	return b
}

// registerExposure serves ExposureService, GraphService and PostureService
// on the public API (G0 M10 D27–D31), as pc_app.
func registerExposure(rs *connect.Server, d apiDeps) {
	ents := exposureEnts(d.billing)
	exposure, graphs := exposurerpc.New(&exapp.Service{Pool: d.pool, Ents: ents})
	pantherclawv1connect.RegisterExposureServiceHandler(rs, exposure)
	pantherclawv1connect.RegisterGraphServiceHandler(rs, graphs)
	pantherclawv1connect.RegisterPostureServiceHandler(rs, posturerpc.New(&poapp.Service{Pool: d.pool, Ents: ents}))
}

// registerExposureJobs adds the breach-radius recomputation (D27, F258):
// a dispatcher every 30 s and a per-org job that follows the feed.
func registerExposureJobs(jobsSoFar []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, b *billing.Service,
	log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	periodic, err := recompute.Register(reg, &recompute.Service{
		Pool: pool, Ents: exposureEnts(b), Failures: &failures.Sink{}, Log: log,
		// Unused-authority findings queue their suggestions (G0 M16 D91).
		Findings: &sgapp.Queue{},
	})
	if err != nil {
		return nil, err
	}
	return append(jobsSoFar, periodic...), nil
}

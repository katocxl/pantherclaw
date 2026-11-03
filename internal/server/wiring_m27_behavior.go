// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/behavior/adapters/behaviorrpc"
	bapp "github.com/katocxl/pantherclaw/internal/behavior/app"
	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

// registerM27Behavior serves BehaviorService on the public API (G0 M27 D501,
// D502), as pc_app.
func registerM27Behavior(rs *connect.Server, d apiDeps) {
	pantherclawv1connect.RegisterBehaviorServiceHandler(rs,
		behaviorrpc.New(&bapp.Service{Pool: d.pool, Ents: opsEnts(d.billing)}))
}

// registerM27BehaviorJobs adds the rollup: an hourly dispatcher and one
// idempotent job per org. It runs off the decision path (HR-641).
func registerM27BehaviorJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, bill *billing.Service,
	log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	r := &bapp.Rollup{Pool: pool, Ents: opsEnts(bill), Raiser: m10Raiser{pool: pool}, Failures: &failures.Sink{}}
	p, err := bapp.RegisterRollup(reg, r, log)
	if err != nil {
		return nil, err
	}
	return append(periodic, p...), nil
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	coverage "github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/sandboxes/adapters/sandboxrpc"
	sandboxes "github.com/katocxl/pantherclaw/internal/sandboxes/app"
)

// registerSandbox serves SandboxService on the public API (G0 M9 track B),
// as pc_app. Closures go to coverage in the session's transaction.
func registerSandbox(rs *connect.Server, d apiDeps) {
	svc := &sandboxes.Service{Pool: d.pool, Coverage: &coverage.Service{Pool: d.pool, Freshness: d.freshness}}
	pantherclawv1connect.RegisterSandboxServiceHandler(rs, sandboxrpc.New(svc))
}

// registerSandboxJobs adds the sandbox's background jobs (the expiry sweep,
// design decision 9) and returns their schedule.
func registerSandboxJobs(reg *jobs.Registry, pool *db.Pool, log *slog.Logger) ([]*river.PeriodicJob, error) {
	return sandboxes.RegisterExpiry(reg, &sandboxes.Service{Pool: pool}, log)
}

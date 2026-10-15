// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/response/sweep"
)

// registerResponseJobs adds the containment confirmation sweep (G0 M10
// D22, HR-249) and returns its schedule.
func registerResponseJobs(reg *jobs.Registry, pool *db.Pool, log *slog.Logger) ([]*river.PeriodicJob, error) {
	return sweep.Register(reg, &sweep.Sweeper{Pool: pool}, log)
}

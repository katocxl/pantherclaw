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
	"github.com/katocxl/pantherclaw/internal/policy/adapters/exceptionsrpc"
	"github.com/katocxl/pantherclaw/internal/policy/exceptions"
)

// policyExceptions builds the exception service (G0 M11.1 D14) as pc_app,
// telling owners through the M5 notifier when there is one.
func policyExceptions(pool *db.Pool, notify exceptions.Notifier) *exceptions.Service {
	return &exceptions.Service{Pool: pool, Notify: notify}
}

// registerPolicyExceptions serves PolicyExceptionService on the public API.
func registerPolicyExceptions(rs *connect.Server, d apiDeps) {
	var notify exceptions.Notifier
	if d.m5 != nil && d.m5.notifications != nil {
		notify = d.m5.notifications
	}
	pantherclawv1connect.RegisterPolicyExceptionServiceHandler(rs, exceptionsrpc.New(policyExceptions(d.pool, notify)))
}

// registerPolicyExceptionJobs adds the exception sweep (expiry and the
// owner's notice a day before it) and returns its schedule.
func registerPolicyExceptionJobs(reg *jobs.Registry, pool *db.Pool, notify exceptions.Notifier, log *slog.Logger) (
	[]*river.PeriodicJob, error,
) {
	return exceptions.RegisterSweep(reg, policyExceptions(pool, notify), log)
}

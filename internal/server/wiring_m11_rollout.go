// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/policy/adapters/rolloutrpc"
	"github.com/katocxl/pantherclaw/internal/policy/rollout"
)

// policyRollouts is the policy rollout service (G0 M11.1, D12, D13).
// Editions come from the licence (without one: Community, no shadow,
// pilots or cohorts). The sweeper reads decisions through the replay
// engine, read ports only (HR-232). Without the publish gate (D6) no
// pilot starts and no rollout completes (fail closed).
func policyRollouts(pool *db.Pool, bill *billing.Service, m5 *m5Services, kp keys.KeyProvider, log *slog.Logger) *rollout.Service {
	svc := &rollout.Service{Pool: pool, Replay: replayEngine(pool, kp), Log: log}
	if bill != nil {
		svc.Editions = bill
	}
	if m5 != nil {
		svc.Notify = m5.notifications
	}
	return svc
}

// registerPolicyRollouts serves PolicyRolloutService on the public API, as
// pc_app.
func registerPolicyRollouts(rs *connect.Server, d apiDeps) {
	pantherclawv1connect.RegisterPolicyRolloutServiceHandler(rs, rolloutrpc.New(policyRollouts(d.pool, d.billing, d.m5, d.kp, d.log)))
}

// registerPolicyRolloutJobs adds the rollout sweeper to reg and returns
// jobs with its schedule appended.
func registerPolicyRolloutJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, bill *billing.Service, m5 *m5Services,
	kp keys.KeyProvider, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	if err := rollout.Register(reg, policyRollouts(pool, bill, m5, kp, log)); err != nil {
		return nil, err
	}
	return append(periodic, rollout.PeriodicJobs()...), nil
}

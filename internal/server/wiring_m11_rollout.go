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
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/rollout"
)

// The policy versions PolicyService serves record a rollout for every
// publication (D6's OnPublished hook) and enter a pilot when its ROLLOUT
// change request is approved on the policy changes page (D11, D12).
func init() {
	policyGateExtensions = append(policyGateExtensions, func(d apiDeps, v *policyapp.Versions) {
		svc := policyRollouts(d.pool, d.billing, d.m5, d.kp, d.log)
		svc.Gate = rollout.Connect(v, svc)
	})
}

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
// pc_app. Its pilots and completions go through the publish gate of policy
// versions of their own, connected like PolicyService's: requests are rows,
// so the page that confirms them applies them with PolicyService's.
func registerPolicyRollouts(rs *connect.Server, d apiDeps) {
	var notify policyapp.Notifier
	if d.m5 != nil && d.m5.notifications != nil {
		notify = d.m5.notifications
	}
	svc := policyRollouts(d.pool, d.billing, d.m5, d.kp, d.log)
	svc.Gate = rollout.Connect(newPolicyVersions(d.pool, notify, d.publicURL), svc)
	pantherclawv1connect.RegisterPolicyRolloutServiceHandler(rs, rolloutrpc.New(svc))
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

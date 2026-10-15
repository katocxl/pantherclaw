// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/cohorts"
	"github.com/katocxl/pantherclaw/internal/cohorts/cohortsrpc"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/packs"
	"github.com/katocxl/pantherclaw/internal/policy/packs/packsrpc"
	"github.com/katocxl/pantherclaw/internal/promotions"
	"github.com/katocxl/pantherclaw/internal/promotions/promotionsrpc"
)

// registerM11Govern serves the production promotion gate's PromotionService,
// fleet cohorts and the reference packs (G0 M11 part 2, D39–D41), as
// pc_app. Cohorts and packs need the Team edition (without a licence the
// server is Community: refused). Packs draft through the policy versions
// API, so a pack's draft passes the same checks and publish gate as any.
func registerM11Govern(rs *connect.Server, d apiDeps) {
	pantherclawv1connect.RegisterPromotionServiceHandler(rs, promotionsrpc.New(&promotions.Service{Pool: d.pool}))
	cs := &cohorts.Service{Pool: d.pool}
	ps := &packs.Service{Pool: d.pool}
	if d.billing != nil {
		cs.Editions, ps.Editions = d.billing, d.billing
	}
	var notify policyapp.Notifier
	if d.m5 != nil && d.m5.notifications != nil {
		notify = d.m5.notifications
	}
	ps.Drafts = newPolicyVersions(d.pool, notify, d.publicURL, d.cel)
	pantherclawv1connect.RegisterCohortServiceHandler(rs, cohortsrpc.New(cs))
	pantherclawv1connect.RegisterPackServiceHandler(rs, packsrpc.New(ps))
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/cohorts"
	"github.com/katocxl/pantherclaw/internal/cohorts/cohortsrpc"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/packs"
	"github.com/katocxl/pantherclaw/internal/policy/packs/packsrpc"
	"github.com/katocxl/pantherclaw/internal/promotions"
	"github.com/katocxl/pantherclaw/internal/promotions/promotionsrpc"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

// registerM11Govern serves the production promotion gate's PromotionService,
// its promotions page, fleet cohorts and the reference packs (G0 M11 part
// 2, D39–D41, D53), as pc_app. Cohorts and packs need the Team edition
// (without a licence the server is Community: refused). Packs draft
// through the policy versions API, so a pack's draft passes the same
// checks and publish gate as any.
func registerM11Govern(rs *connect.Server, d apiDeps) {
	prom := newPromotions(d.pool)
	pantherclawv1connect.RegisterPromotionServiceHandler(rs, promotionsrpc.New(prom))
	if d.web != nil {
		d.web.WithPromotions(prom) // the only way to promote: a step-up is a browser session's (D53)
	}
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

// newPromotionGate is the production promotion gate grants call when they
// issue a grant or store a widening revision, and the automation issuer
// when it issues one (D9, D39, D70, HR-290).
func newPromotionGate(pool *db.Pool) grantsapp.PromotionGate {
	return promotions.Gate{Packages: &defspg.Store{Pool: pool}}
}

// newPromotions is the promotion service: its checks read the definitions
// a prefix covers, and a lapsed provisional promotion is an owned failure
// for the agent's owner (D80).
func newPromotions(pool *db.Pool) *promotions.Service {
	return &promotions.Service{Pool: pool, Packages: &defspg.Store{Pool: pool}, Failures: &failures.Sink{}}
}

// registerM11GovernJobs adds the provisional promotion sweep (every 5
// minutes: confirm those whose coverage appeared, expire the lapsed ones)
// and returns jobs with its schedule appended.
func registerM11GovernJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, log *slog.Logger) ([]*river.PeriodicJob, error) {
	p, err := promotions.RegisterSweep(reg, newPromotions(pool), log)
	if err != nil {
		return nil, err
	}
	return append(periodic, p...), nil
}

// newGrants is the grants store and service of the API and of a
// worker-only process, both with the production promotion gate (D9, D80,
// D81, D93): the store runs it in Issue's, a widening Revise's and
// Delegate's transaction, and automation issuance in the engine's; each
// caps the grant at a provisional promotion's expiry from the rows the
// gate read.
func newGrants(pool *db.Pool) (*grantspg.Store, *grantsapp.Service) {
	gate := newPromotionGate(pool)
	gstore := &grantspg.Store{Pool: pool, Promotions: gate}
	return gstore, &grantsapp.Service{
		Repo: gstore, Subjects: gstore, Defs: &defspg.Store{Pool: pool}, Authz: grantsapp.SubjectAuthorizer{},
		Clock: clock.System{}, Listing: gstore, Refusals: gstore, Store: gstore, Promotions: gate,
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"
	"net/http"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/bundles/adapters/bundlerpc"
	bundlesapp "github.com/katocxl/pantherclaw/internal/bundles/app"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
)

// The M37 publisher and bundle wiring (G0 M37 D1081–D1083): BundleService,
// the publisher pin activation page and the daily revocation fetch. Each
// item kind routes into its own use case: custom rules (reflex), drafts and
// pauses (automations), package version withdrawal (definitions).

// newBundles builds the service as pc_app; nil without a pool.
func newBundles(pool *db.Pool, bill *billing.Service, limits celenv.Limits, autos *automationsCore, notify *napp.Service,
	publicURL string, log *slog.Logger,
) *bundlesapp.Service {
	if pool == nil {
		return nil
	}
	reflex := newReflexCore(pool, limits, bill, nil, log)
	det := &reflexapp.Detections{Pool: pool, PackErr: reflex.packErr, Env: reflex.env}
	if bill != nil {
		det.Ents = bill
	}
	deps := bundlesapp.Deps{Rules: det, Versions: &defspg.Store{Pool: pool}}
	if autos != nil && autos.svc != nil {
		deps.Automations = autos.svc
	}
	if notify != nil {
		deps.Notify = notify
	}
	return bundlesapp.New(pool, deps, bundlesapp.Config{PublicURL: publicURL}, clock.System{}, log)
}

// registerM37Bundles serves BundleService and returns the pin page's
// mount; nil when the service cannot run.
func registerM37Bundles(rs *connect.Server, d apiDeps, autos *automationsCore) func(mux *http.ServeMux) {
	var notify *napp.Service
	if d.m5 != nil {
		notify = d.m5.notifications
	}
	svc := newBundles(d.pool, d.billing, d.cel, autos, notify, d.publicURL, d.log)
	if svc == nil {
		return nil
	}
	pantherclawv1connect.RegisterBundleServiceHandler(rs, bundlerpc.New(svc))
	if d.web == nil {
		return nil
	}
	web := d.web
	return func(mux *http.ServeMux) { web.MountPublisherPins(mux, svc) }
}

// registerM37BundlesJobs adds the daily revocation fetch.
func registerM37BundlesJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, bill *billing.Service,
	limits celenv.Limits, autos *automationsCore, notify *napp.Service, publicURL string, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	svc := newBundles(pool, bill, limits, autos, notify, publicURL, log)
	if svc == nil {
		return periodic, nil
	}
	p, err := bundlesapp.RegisterJobs(reg, svc)
	if err != nil {
		return nil, err
	}
	return append(periodic, p...), nil
}

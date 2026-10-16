// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/automations/adapters/automationsrpc"
	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/changes"
	"github.com/katocxl/pantherclaw/internal/changes/adapters/changesrpc"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
)

// automationsCore is the M11 part 2 core (D5–D10, D14, D15): the generic
// change-request ceremony, the automations app and the grants and runs
// services wired for automation issuance. The other M11 streams reach it
// here: protect registers its change kinds on changes, the engine issues
// through grants and runs, triggers and assurance set the app's ports.
type automationsCore struct {
	changes *changes.Service
	svc     *autoapp.Service
	grants  *grantsapp.Service
	runs    *runsapp.Service
}

// newAutomationsCore builds the core services. grants and runs are the API's
// own services: they gain the automation ceilings, the in-transaction
// store and the daily run cap.
func newAutomationsCore(pool *db.Pool, bill *billing.Service, publicURL string, grants *grantsapp.Service, runs *runsapp.Service) *automationsCore {
	ch := changes.New(pool, publicURL)
	svc := &autoapp.Service{
		Pool: pool, Clock: clock.System{}, Changes: ch, Grants: grants, Runs: runs,
		Operations: &defspg.Store{Pool: pool}, Failures: &failures.Sink{},
	}
	if bill != nil {
		svc.Editions = bill
	}
	svc.RegisterChanges()
	if grants != nil {
		if grants.Store == nil {
			grants.Store = &grantspg.Store{Pool: pool}
		}
		grants.Ceilings = svc
	}
	if runs != nil {
		runs.WithAutomationRuns(svc)
	}
	return &automationsCore{changes: ch, svc: svc, grants: grants, runs: runs}
}

// registerAutomationsCore serves AutomationService and ChangeService,
// mounts the /changes pages when security keys are configured, and lets
// the kill switch pause every automation (D14).
func registerAutomationsCore(rs *connect.Server, d apiDeps, grants *grantsapp.Service, runs *runsapp.Service) *automationsCore {
	core := newAutomationsCore(d.pool, d.billing, d.publicURL, grants, runs)
	pantherclawv1connect.RegisterAutomationServiceHandler(rs, automationsrpc.New(core.svc))
	pantherclawv1connect.RegisterChangeServiceHandler(rs, changesrpc.New(core.changes))
	if d.web != nil && d.m5 != nil && d.m5.webauthn != nil {
		d.web.WithChanges(core.changes, d.m5.webauthn)
	}
	if d.m6 != nil && d.m6.response != nil {
		d.m6.response.WithPauser(core.svc)
	}
	return core
}

// identities lists automations for ListAgents (D15).
func (c *automationsCore) identities(ctx context.Context) ([]*pantherclawv1.AutomationIdentity, string, error) {
	if c == nil {
		return nil, "automations are not available on this server", nil
	}
	xs, note, err := c.svc.Identities(ctx)
	if err != nil {
		return nil, "", err
	}
	out := make([]*pantherclawv1.AutomationIdentity, 0, len(xs))
	for _, x := range xs {
		out = append(out, automationsrpc.IdentityPB(x))
	}
	return out, note, nil
}

// registerAutomationsCoreJobs adds the ceiling sweep (D57) and returns
// periodic with its schedule appended.
func registerAutomationsCoreJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, bill *billing.Service, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	gstore := &grantspg.Store{Pool: pool}
	grants := &grantsapp.Service{
		Repo: gstore, Subjects: gstore, Defs: &defspg.Store{Pool: pool}, Authz: grantsapp.SubjectAuthorizer{},
		Clock: clock.System{}, Store: gstore,
	}
	core := newAutomationsCore(pool, bill, "", grants, runsapp.New(pool).WithGrants(gstore))
	// The ceiling sweep counts no approver marked compromised (G0 M11 D43).
	core.svc.Compromise = &protect.Publishers{Pool: pool}
	if err := core.svc.RegisterJobs(reg, log); err != nil {
		return nil, err
	}
	return append(periodic, autoapp.PeriodicJobs()...), nil
}

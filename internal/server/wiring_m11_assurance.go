// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	"github.com/katocxl/pantherclaw/internal/automations/assurance/adapters/assurancerpc"
	"github.com/katocxl/pantherclaw/internal/billing"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

// assuranceService is the assurance use cases over pool; without a licence
// service every use case fails closed with EDITION_REQUIRED.
func assuranceService(pool *db.Pool, bill *billing.Service) *assurance.Service {
	svc := &assurance.Service{Pool: pool}
	if bill != nil {
		svc.Ents = bill
	}
	return svc
}

// assurancePorts sets the shared automations core's TestGate (D34) and
// RolloutEvidence (D36) to assurance's (D96): without them enabling a
// version and widening a rollout always fail.
func assurancePorts(core *automationsCore) {
	if core != nil && core.svc != nil {
		core.svc.TestGate = assurance.TestGate{}
		core.svc.Rollout = assurance.RolloutEvidence{}
	}
}

// registerAutomationAssurance serves AssuranceService (G0 M11 part 2
// D34–D38, D59) as pc_app and gives the shared core its assurance ports;
// a simulation's job is enqueued in the transaction that stores it.
func registerAutomationAssurance(rs *connect.Server, d apiDeps, core *automationsCore) error {
	assurancePorts(core)
	insert, err := jobs.NewClient(d.pool, nil, jobs.Config{Logger: d.log}) // insert-only
	if err != nil {
		return err
	}
	svc := assuranceService(d.pool, d.billing)
	svc.Jobs = insert
	pantherclawv1connect.RegisterAssuranceServiceHandler(rs, assurancerpc.New(svc))
	return nil
}

// assuranceIssuer is the grants service a simulation previews launches
// with (DryRun, D94 S5), its ceilings checked by a core of its own.
func assuranceIssuer(pool *db.Pool, bill *billing.Service) *grantsapp.Service {
	gstore := &grantspg.Store{Pool: pool}
	grants := &grantsapp.Service{
		Repo: gstore, Subjects: gstore, Defs: &defspg.Store{Pool: pool}, Authz: grantsapp.SubjectAuthorizer{},
		Clock: clock.System{}, Store: gstore,
	}
	newAutomationsCore(pool, bill, "", grants, nil) // sets grants.Ceilings
	return grants
}

// registerAutomationAssuranceJobs adds the historical-simulation worker
// (D35) and the sweep that raises the derived automation exceptions (D38).
func registerAutomationAssuranceJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, bill *billing.Service,
	log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	svc := assuranceService(pool, bill)
	svc.Issuer = assuranceIssuer(pool, bill)
	if err := assurance.RegisterJobs(reg, svc, log); err != nil {
		return nil, err
	}
	sweep, err := assurance.RegisterSweep(reg, pool, &failures.Sink{})
	if err != nil {
		return nil, err
	}
	return append(periodic, sweep...), nil
}

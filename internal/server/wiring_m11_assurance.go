// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	"github.com/katocxl/pantherclaw/internal/automations/assurance/adapters/assurancerpc"
	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
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

// registerAutomationAssurance serves AssuranceService (G0 M11 part 2
// D34–D38, D59) as pc_app; a simulation's job is enqueued in the
// transaction that stores it.
func registerAutomationAssurance(rs *connect.Server, d apiDeps) error {
	insert, err := jobs.NewClient(d.pool, nil, jobs.Config{Logger: d.log}) // insert-only
	if err != nil {
		return err
	}
	svc := assuranceService(d.pool, d.billing)
	svc.Jobs = insert
	pantherclawv1connect.RegisterAssuranceServiceHandler(rs, assurancerpc.New(svc))
	return nil
}

// registerAutomationAssuranceJobs adds the historical-simulation worker
// (D35).
func registerAutomationAssuranceJobs(reg *jobs.Registry, pool *db.Pool, bill *billing.Service, log *slog.Logger) error {
	return assurance.RegisterJobs(reg, assuranceService(pool, bill), log)
}

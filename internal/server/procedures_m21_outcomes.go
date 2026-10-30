// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"
	"maps"

	"connectrpc.com/connect/v2"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/outcomes"
	"github.com/katocxl/pantherclaw/internal/outcomes/adapters/outcomesrpc"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m21OutcomeProcedures are OutcomeService's procedures (G0 M21 D303):
// operations.read; each metric then needs its sources' read permissions.
var m21OutcomeProcedures = map[string]td.Permission{
	pantherclawv1connect.OutcomeServiceGetOutcomeMetricsProcedure: td.PermOperationsRead,
}

func init() { maps.Copy(procedurePermissions, m21OutcomeProcedures) }

// registerM21Outcomes registers OutcomeService.
func registerM21Outcomes(rs *connect.Server, d apiDeps) {
	pantherclawv1connect.RegisterOutcomeServiceHandler(rs,
		outcomesrpc.New(&outcomes.Service{Pool: d.pool, Ents: opsEnts(d.billing)}))
}

// registerM21OutcomeJobs adds the nightly rollup: an hourly dispatcher and
// one idempotent job per org.
func registerM21OutcomeJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, bill *billing.Service,
	log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	p, err := outcomes.RegisterRollup(reg, &outcomes.Rollup{Pool: pool, Ents: opsEnts(bill), Failures: &failures.Sink{}}, log)
	if err != nil {
		return nil, err
	}
	return append(periodic, p...), nil
}

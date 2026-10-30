// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"
	"maps"

	"github.com/riverqueue/river"

	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m18FleetProcedures are the gateway fleet procedures (G0 M18 D151, D161):
// the fleet policy takes the permission CreateGateway uses, the fleet view
// gateway read.
var m18FleetProcedures = map[string]td.Permission{
	pantherclawv1connect.GatewayAdminServiceGetFleetPolicyProcedure: td.PermGatewayManage,
	pantherclawv1connect.GatewayAdminServiceSetFleetPolicyProcedure: td.PermGatewayManage,
	pantherclawv1connect.GatewayAdminServiceListFleetProcedure:      td.PermGatewayRead,
}

func init() { maps.Copy(procedurePermissions, m18FleetProcedures) }

// registerM18FleetJobs adds the per-org fleet sweep: silence, recovery and
// below-minimum alerts (G0 M18 D151, HR-471).
func registerM18FleetJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, fleet *gwapp.Fleet, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	if err := fleet.RegisterJobs(reg, log); err != nil {
		return nil, err
	}
	return append(periodic, gwapp.FleetPeriodicJobs()...), nil
}

// newM18Fleet builds the fleet use cases over the M6 gateway service: the
// licence decides the editions per org, notify sends the sweep's alerts.
func newM18Fleet(m6 *m6Services, editions gwapp.Editions, notify gwapp.Notifier) *gwapp.Fleet {
	return gwapp.NewFleet(m6.gateways, editions, notify)
}

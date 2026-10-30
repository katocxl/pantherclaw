// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"
	"maps"

	"github.com/riverqueue/river"

	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m15GatewayProcedures are the M15 gateway procedures (G0 M15 D6, D10,
// D12): status reports and the gateway's shared MCP state. GatewayHandler
// serves them on the gateway listener.
var m15GatewayProcedures = map[string]td.Permission{
	pantherclawv1connect.GatewayServiceReportStatusProcedure:   "gateway.observe",
	pantherclawv1connect.GatewayServicePutMCPStateProcedure:    "gateway.sync",
	pantherclawv1connect.GatewayServiceGetMCPStateProcedure:    "gateway.sync",
	pantherclawv1connect.GatewayServiceDeleteMCPStateProcedure: "gateway.sync",
}

func init() { maps.Copy(procedurePermissions, m15GatewayProcedures) }

// registerM15GatewayJobs adds the replica prune and the MCP state purge
// (G0 M15 D11, D12).
func registerM15GatewayJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	if err := gwapp.New(pool, nil, "", clock.System{}).RegisterJobs(reg, log); err != nil {
		return nil, err
	}
	return append(periodic, gwapp.PeriodicJobs()...), nil
}

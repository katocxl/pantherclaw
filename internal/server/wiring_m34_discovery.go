// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"
	"maps"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	saasapp "github.com/katocxl/pantherclaw/internal/saasdiscovery/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The M34 discovery stream's wiring (G0 M34 D997): daily scans of SaaS and
// cloud agent runtime connections.

var m34DiscoveryProcedures = map[string]td.Permission{
	pantherclawv1connect.SaasDiscoveryServiceSetSaaSScanScheduleProcedure: td.PermAgentManage,
}

// Setting a schedule makes the server send the connection's credential to
// work every day as the person who set it, as starting a scan does: a
// change.
var m34DiscoveryClasses = map[string]entitlements.Class{
	pantherclawv1connect.SaasDiscoveryServiceSetSaaSScanScheduleProcedure: entitlements.ClassChange,
}

func init() {
	maps.Copy(procedurePermissions, m34DiscoveryProcedures)
	maps.Copy(procedureClasses, m34DiscoveryClasses)
}

// registerM34DiscoveryJobs registers the daily scheduled-scan workers, next
// to the GitHub daily scans, and returns periodic with their dispatcher.
func registerM34DiscoveryJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, bill *billing.Service, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	s := &saasapp.Scheduler{Pool: pool, Log: log}
	if bill != nil {
		s.Editions = bill
	}
	if err := saasapp.Register(reg, s); err != nil {
		return nil, err
	}
	return append(periodic, saasapp.PeriodicJobs()...), nil
}

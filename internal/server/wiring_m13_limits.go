// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"
	"maps"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	usagemeter "github.com/katocxl/pantherclaw/internal/usage"
)

// M13 limits (G0 M13 D8-D11, D27): the authenticated API's rate limits per
// organization and credential (HR-375), the shared limiter's janitor
// (HR-376; the inbound endpoint and AuthZEN count in it themselves), and
// the daily usage meters with UsageService (HR-377).

// m13UsageProcedures are UsageService's procedures (D11): reading the
// org's metered usage. Nothing in the API writes usage (HR-377).
var m13UsageProcedures = map[string]td.Permission{
	pantherclawv1connect.UsageServiceListUsageProcedure: td.PermEntitlementsRead,
}

func init() { maps.Copy(procedurePermissions, m13UsageProcedures) }

// ProcedurePermissions returns a copy of every served procedure's declared
// permission (the range's api.flood step authenticates with it).
func ProcedurePermissions() map[string]td.Permission { return maps.Clone(procedurePermissions) }

// APILimits is the rpcauth option of limits.api.* (per replica).
// Procedures the plan gate classes safety or allow skip the per-org limit
// and are counted per credential only (D27).
func (c *Config) APILimits() rpcauth.Option {
	return rpcauth.WithAPILimits(rpcauth.APILimits{
		PerOrg: c.Limits.API.PerOrgPerMinute, PerCredential: c.Limits.API.PerCredentialPerMinute,
		OrgExempt: orgLimitExempt,
	})
}

// orgLimitExempt reports procedures that skip the per-org API limit: the
// plan gate's safety and allow classes (D27).
func orgLimitExempt(procedure string) bool {
	c := procedureClass(procedure)
	return c == entitlements.ClassSafety || c == entitlements.ClassAllow
}

// registerLimitsJobs adds the shared limiter's janitor and the usage
// meters, and returns their schedules appended to periodic.
func registerLimitsJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	if err := ratelimit.RegisterJanitor(reg, pool, log); err != nil {
		return nil, err
	}
	if err := usagemeter.Register(reg, usagemeter.New(pool, nil), log); err != nil {
		return nil, err
	}
	return append(append(periodic, ratelimit.JanitorPeriodicJobs()...), usagemeter.PeriodicJobs()...), nil
}

// usageService serves UsageService.
type usageService struct {
	pantherclawv1connect.UnimplementedUsageServiceHandler
	svc *usagemeter.Service
}

// registerUsage serves UsageService.
func registerUsage(rs *connect.Server, d apiDeps) {
	pantherclawv1connect.RegisterUsageServiceHandler(rs, usageService{svc: usagemeter.New(d.pool, nil)})
}

// ListUsage implements UsageServiceHandler.
func (s usageService) ListUsage(ctx context.Context, req *pantherclawv1.ListUsageRequest) (*pantherclawv1.ListUsageResponse, error) {
	days, err := s.svc.List(ctx, int(req.GetDays()))
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListUsageResponse{Days: make([]*pantherclawv1.DailyUsage, 0, len(days))}
	for _, d := range days {
		out.Days = append(out.Days, &pantherclawv1.DailyUsage{
			Day: d.Day.UTC().Format(time.DateOnly), Agents: int32(d.Agents), InstancesPeak: int32(d.InstancesPeak), //nolint:gosec // G115: counts
			Runs: int32(d.Runs), StoredBytes: d.StoredBytes, //nolint:gosec // G115: counts
		})
	}
	return out, nil
}

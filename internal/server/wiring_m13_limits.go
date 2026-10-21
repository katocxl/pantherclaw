// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
)

// M13 limits (G0 M13 D8-D11): the authenticated API's rate limits per
// organization and credential (HR-375), the shared limiter's janitor
// (HR-376; the inbound endpoint and AuthZEN count in it themselves).

// apiLimits is the rpcauth option of limits.api.* (per replica).
func (c *Config) apiLimits() rpcauth.Option {
	return rpcauth.WithAPILimits(rpcauth.APILimits{
		PerOrg: c.Limits.API.PerOrgPerMinute, PerCredential: c.Limits.API.PerCredentialPerMinute,
	})
}

// registerLimitsJobs adds the shared limiter's janitor and returns its
// schedule appended to periodic.
func registerLimitsJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	if err := ratelimit.RegisterJanitor(reg, pool, log); err != nil {
		return nil, err
	}
	return append(periodic, ratelimit.JanitorPeriodicJobs()...), nil
}

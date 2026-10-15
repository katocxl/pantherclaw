// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/coverage/adapters/coveragerpc"
	covapp "github.com/katocxl/pantherclaw/internal/coverage/app"
	coverage "github.com/katocxl/pantherclaw/internal/coverage/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// registerCoverage serves CoverageService on the public API (G0 M9 track
// A), as pc_app.
func registerCoverage(rs *connect.Server, d apiDeps) {
	svc := &covapp.Service{Pool: d.pool, Freshness: d.freshness, Verifier: covapp.ConnectionTests{}}
	protectCoverage(svc, d.m11protect)
	if d.m5 != nil && d.m5.notifications != nil {
		svc.Notify = d.m5.notifications
	}
	pantherclawv1connect.RegisterCoverageServiceHandler(rs, coveragerpc.New(svc))
}

// freshnessOf returns the configured freshness contract; Validate has
// checked it, so an error only falls back to the defaults.
func freshnessOf(cfg *Config) coverage.Freshness {
	f, err := cfg.freshness()
	if err != nil {
		f, _ = coverage.NewFreshness(0, 0)
	}
	return f
}

// registerCoverageWorkers adds the coverage reassess job (HR-211) and
// returns its schedule.
func registerCoverageWorkers(reg *jobs.Registry, cfg *Config, pool *db.Pool) ([]*river.PeriodicJob, error) {
	f := freshnessOf(cfg)
	if err := covapp.Register(reg, &covapp.Service{Pool: pool, Freshness: f, Verifier: covapp.ConnectionTests{}}); err != nil {
		return nil, err
	}
	return covapp.PeriodicJobs(f), nil
}

// coverageClaims gives decision receipts the coverage claim of their scope
// (HR-217).
type coverageClaims struct{ svc *covapp.Service }

func (c coverageClaims) CoverageClaim(ctx context.Context, org ids.OrgID, agent, connection ids.UUID, operation string,
	at time.Time,
) (*finalize.CoverageClaim, error) {
	sc := coverage.Scope{Agent: agent, Connection: connection, Operation: operation}
	claim, err := c.svc.ClaimAt(ctx, org, sc, at)
	if err != nil || claim == nil {
		return nil, err
	}
	out := &finalize.CoverageClaim{
		V: 1, State: claim.State.String(), Snapshot: claim.Snapshot.String(),
		Scope:         finalize.CoverageClaimScope{Agent: agent.String(), Connection: connection.String(), Operation: operation},
		SnapshotState: claim.SnapshotState.String(), Lapsed: claim.Lapsed, Reason: claim.Reason,
		Exclusions: append([]string{}, claim.Exclusions...),
	}
	if claim.ExpiresAt != nil {
		out.ExpiresAt = evdomain.Timestamp(*claim.ExpiresAt)
	}
	return out, nil
}

// mountCoveragePages adds the coverage list and card, which only read
// (G0 M9 slice A8).
func mountCoveragePages(web *webhttp.Handler, pool *db.Pool, cfg *Config) {
	f := freshnessOf(cfg)
	web.WithCoverage(&covapp.Service{Pool: pool, Freshness: f, Verifier: covapp.ConnectionTests{}}, f)
}

// claimTimeoutOf returns the configured claim timeout; Validate has
// checked it, so an error only falls back to the default.
func claimTimeoutOf(cfg *Config) time.Duration {
	d, err := cfg.claimTimeout()
	if err != nil {
		return finalize.DefaultClaimTimeout
	}
	return d
}

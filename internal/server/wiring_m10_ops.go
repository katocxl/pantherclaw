// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/riverqueue/river"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/token"
	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/operations"
	"github.com/katocxl/pantherclaw/internal/operations/adapters/operationsrpc"
	"github.com/katocxl/pantherclaw/internal/operations/stream"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

// m10OpsDeps are what the Operations surface needs beyond apiDeps: the
// bearer authenticator and the token service, for the live stream.
type m10OpsDeps struct {
	authn  *authnapp.Authenticator
	tokens *token.Service
}

// registerM10Ops registers OperationsService (G0 M10 D33; SearchService:
// registerM11Search) and returns the function that mounts the live stream (D32,
// HR-256) on the API mux.
func registerM10Ops(rs *connect.Server, d apiDeps) (func(*http.ServeMux), error) {
	pantherclawv1connect.RegisterOperationsServiceHandler(rs,
		operationsrpc.New(&operations.Service{Pool: d.pool, Clock: clock.System{}, Sources: opsSources(d), Ents: opsEnts(d.billing)}))
	if d.m10ops.authn == nil {
		return func(*http.ServeMux) {}, nil // no bearer authentication configured (tests)
	}
	tokens := d.m10ops.tokens
	expiry := func(bearer string) (time.Time, bool) {
		if tokens == nil {
			return time.Time{}, false
		}
		v, err := tokens.Verify(bearer, time.Now())
		if err != nil {
			return time.Time{}, false
		}
		return v.ExpiresAt, true
	}
	h, err := stream.New(stream.PoolFeed{Pool: d.pool}, d.m10ops.authn, stream.PoolScoper{Pool: d.pool}, expiry,
		clock.System{}, stream.Config{}, d.log)
	if err != nil {
		return nil, err
	}
	return h.Mount, nil
}

// opsEnts is the licence as metrics read it; nil refuses them (D5).
func opsEnts(b *billing.Service) operations.Entitlements {
	if b == nil {
		return nil
	}
	return b
}

// registerM10OpsJobs adds the hourly operating-metrics collection (D33):
// a dispatcher every 15 minutes and one idempotent job per org.
func registerM10OpsJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, bill *billing.Service,
	log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	p, err := operations.RegisterMetrics(reg, &operations.Collector{Pool: pool, Ents: opsEnts(bill), Failures: &failures.Sink{}}, log)
	if err != nil {
		return nil, err
	}
	return append(periodic, p...), nil
}

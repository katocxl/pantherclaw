// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/billing"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/postureview/adapters/queuerpc"
	"github.com/katocxl/pantherclaw/internal/postureview/adapters/sources"
	pvapp "github.com/katocxl/pantherclaw/internal/postureview/app"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

// postureSourceFactory builds one source of the ranked posture queue.
type postureSourceFactory func(pool *db.Pool, ents exapp.Entitlements) ports.Source

// postureSourceFactories are the sources beyond the built-in ones (G0 M24
// D204). A stream that owns a source adds it from an init in its own wiring
// file:
//
//	func init() { postureSourceFactories = append(postureSourceFactories, newMySource) }
var postureSourceFactories []postureSourceFactory

// postureSources builds every source.
func postureSources(pool *db.Pool, ents exapp.Entitlements) []ports.Source {
	out := sources.Builtin(sources.Reader{Pool: pool, Ents: ents})
	for _, f := range postureSourceFactories {
		out = append(out, f(pool, ents))
	}
	return out
}

func postureQueue(pool *db.Pool, ents exapp.Entitlements) *pvapp.Service {
	return &pvapp.Service{Pool: pool, Ents: ents, Sources: postureSources(pool, ents)}
}

// registerPostureQueue serves PostureQueueService on the public API (G0 M24
// D200), as pc_app.
func registerPostureQueue(rs *connect.Server, d apiDeps) {
	pantherclawv1connect.RegisterPostureQueueServiceHandler(rs, queuerpc.New(postureQueue(d.pool, exposureEnts(d.billing))))
}

// registerPostureQueueJobs adds the daily posture rollup (G0 M24 D206).
func registerPostureQueueJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, bill *billing.Service,
	log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	p, err := pvapp.RegisterRollup(reg, &pvapp.Rollup{Service: postureQueue(pool, exposureEnts(bill)), Failures: &failures.Sink{}}, log)
	if err != nil {
		return nil, err
	}
	return append(periodic, p...), nil
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/ranges/adapters/pgranges"
	"github.com/katocxl/pantherclaw/internal/ranges/adapters/rangerpc"
	rangeapp "github.com/katocxl/pantherclaw/internal/ranges/app"
)

// registerRanges serves RangeService on the public API (G0 M12 W5), as
// pc_app. Editions come from the licence; without one the server is
// Community.
func registerRanges(rs *connect.Server, d apiDeps, evidence *evapp.Service) {
	svc := &rangeapp.Service{Store: pgranges.Store{Pool: d.pool}, Exporter: rangePacks{evidence}}
	if d.billing != nil {
		svc.Editions = d.billing
	}
	pantherclawv1connect.RegisterRangeServiceHandler(rs, rangerpc.New(svc))
}

// rangePacks exports a finished range's assurance report as an evidence
// pack of scope range; the pack service checks the caller's evidence.export
// and the Team licence again.
type rangePacks struct{ svc *evapp.Service }

func (e rangePacks) ExportRange(ctx context.Context, rng ids.UUID) (ids.UUID, error) {
	p, err := e.svc.CreateEvidencePack(ctx, evapp.PackRequest{
		Kind: pack.ScopeRange, Range: rng, Include: pack.Include{Receipts: true, Versions: true},
	})
	return p.ID, err
}

// registerRangeJobs adds the range's background jobs (the abandon sweep)
// and returns their schedule.
func registerRangeJobs(reg *jobs.Registry, pool *db.Pool, log *slog.Logger) ([]*river.PeriodicJob, error) {
	return pgranges.RegisterAbandon(reg, pool, log)
}

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
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	"github.com/katocxl/pantherclaw/internal/threatmap/adapters/pgthreatmap"
	"github.com/katocxl/pantherclaw/internal/threatmap/adapters/threatmaprpc"
	tmapp "github.com/katocxl/pantherclaw/internal/threatmap/app"
)

// threatMapService is the threat map's use cases (G0 M28 D710), as pc_app.
func threatMapService(pool *db.Pool, ents tmapp.Entitlements) *tmapp.Service {
	return &tmapp.Service{Pool: pool, Ents: ents, Store: pgthreatmap.Store{}}
}

// threatMapPacks is the threat map service for evidence packs of scope
// threat_map (D720): the scope check at create time and the report at build
// time. A nil billing service leaves the service without a licence, which
// fails closed.
func threatMapPacks(pool *db.Pool, bill *billing.Service) *tmapp.Service {
	var ents tmapp.Entitlements
	if bill != nil {
		ents = bill
	}
	return threatMapService(pool, ents)
}

// registerM28ThreatMap serves ThreatMapService (G0 M28 D721); the procedure
// permissions and classes are in procedures_m28_threatmap.go.
func registerM28ThreatMap(rs *connect.Server, d apiDeps) {
	var ents tmapp.Entitlements
	if d.billing != nil {
		ents = d.billing
	}
	pantherclawv1connect.RegisterThreatMapServiceHandler(rs, threatmaprpc.New(threatMapService(d.pool, ents)))
}

// registerM28ThreatMapJobs adds the daily snapshot (D719): a dispatcher
// every threat_map.snapshot_interval and one idempotent job per org.
func registerM28ThreatMapJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, bill *billing.Service,
	cfg ThreatMapConfig, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	s := &tmapp.Snapshotter{Pool: pool, Store: pgthreatmap.Store{}}
	if bill != nil {
		s.Ents = bill
	}
	p, err := tmapp.RegisterSnapshots(reg, s, cfg.SnapshotInterval.D(), log)
	if err != nil {
		return nil, err
	}
	return append(periodic, p...), nil
}

func init() { postureSourceFactories = append(postureSourceFactories, newThreatMapPostureSource) }

// newThreatMapPostureSource reports the threat map's fixable gaps to the
// queue (D724).
func newThreatMapPostureSource(pool *db.Pool, ents exapp.Entitlements) ports.Source {
	var e tmapp.Entitlements
	if ents != nil {
		e = ents
	}
	return &tmapp.Source{Svc: threatMapService(pool, e)}
}

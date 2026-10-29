// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Drift checks (G0 M6 design decision 14, HR-081): the gateway compares
// each kind-mcp connection's upstream tool list with the definitions its
// package was reviewed against when a configuration loads and every
// DriftEvery. A difference is refused at once by the gateway and reported
// (ReportDrift), and the server quarantines the org's pin of that package
// version, which stops every connection using it.
const (
	DriftEvery = 10 * time.Minute
	// driftPoll is how often the loop looks for a new configuration.
	driftPoll = 5 * time.Second
)

// DriftReporter tells the server an upstream tool drifted.
type DriftReporter func(ctx context.Context, connection string, d dispatch.Drift) error

// watchDrift checks for drift on every configuration load and every
// DriftEvery until ctx ends.
func (g *Gateway) watchDrift(ctx context.Context) error {
	checked, next := int64(-1), time.Time{}
	tick := time.NewTicker(g.driftPoll)
	defer tick.Stop()
	for {
		if cfg := g.config.Current(); cfg != nil && (cfg.Version != checked || !time.Now().Before(next)) {
			g.checkDrift(ctx, cfg)
			checked, next = cfg.Version, time.Now().Add(g.driftEvery)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// checkDrift checks every kind-mcp connection of cfg and reports each
// drifted tool. A server that cannot be listed is logged and checked
// again next time.
func (g *Gateway) checkDrift(ctx context.Context, cfg *control.Config) {
	for _, id := range slices.Sorted(maps.Keys(cfg.ByID)) {
		conn := cfg.ByID[id]
		if conn.GetKind() != "mcp" {
			continue
		}
		drifts, err := g.engine.CheckDrift(ctx, conn)
		if err != nil {
			g.log.WarnContext(ctx, "gateway.drift_check_failed", slog.String("connection_id", id), pclog.Err(err))
			continue
		}
		g.status.driftChecked(id, time.Now())
		for _, d := range drifts {
			g.drifted(ctx, id, d)
		}
	}
}

// drifted logs and reports one drifted tool, found by a check of the loop
// or of a call (dispatch.Options.OnDrift).
func (g *Gateway) drifted(ctx context.Context, connection string, d dispatch.Drift) {
	g.log.WarnContext(ctx, "security.upstream_drift", slog.String("connection_id", connection), slog.String("upstream_tool", d.Tool),
		slog.String("expected_digest", d.Expected), slog.String("observed_digest", d.Observed))
	if g.reportDrift == nil {
		return
	}
	if err := g.reportDrift(ctx, connection, d); err != nil {
		g.log.ErrorContext(ctx, "gateway.drift_not_reported", slog.String("connection_id", connection), pclog.Err(err))
	}
}

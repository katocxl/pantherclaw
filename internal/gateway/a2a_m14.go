// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/a2aface"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// a2aPeer returns an a2a connection's pinned peer for the A2A face (G0 M14
// D30, D31, D64): the card as pinned, the binding the gateway calls it
// over and the allowed skills. A connection without a pinned card is not
// served.
func a2aPeer(conn *control.Connection) (a2aface.Peer, bool) {
	c := conn.GetA2A()
	if conn.GetKind() != "a2a" || c == nil || len(c.GetPinnedCard()) == 0 || c.GetInterface() == nil {
		return a2aface.Peer{}, false
	}
	return a2aface.Peer{Card: c.GetPinnedCard(), Binding: c.GetInterface().GetProtocol(), Skills: c.GetSkills()}, true
}

// watchA2ACards reads every a2a connection's card again on each
// configuration load and every DriftEvery (G0 M14 D30, HR-322), as
// watchDrift does for MCP tools: a changed card is refused at once and
// reported; a report the server did not take is retried with backoff
// (D112).
func (g *Gateway) watchA2ACards(ctx context.Context) error {
	checked, next := int64(-1), time.Time{}
	reports := cardReports{}
	tick := time.NewTicker(g.driftPoll)
	defer tick.Stop()
	for {
		if cfg := g.config.Current(); cfg != nil && (cfg.Version != checked || !time.Now().Before(next)) {
			g.checkA2ACards(ctx, cfg, reports)
			checked, next = cfg.Version, time.Now().Add(g.driftEvery)
		}
		g.reportA2ACards(ctx, reports, time.Now())
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// cardReports are the drift reports of a2a connections, by connection: one
// per drift, until the card is the pinned one again.
type cardReports map[string]*cardReport

type cardReport struct {
	drift dispatch.Drift
	sent  bool
	tries int
	next  time.Time
}

// Drift reports are retried after 5 s, doubling up to 5 min.
const (
	cardReportFirst = 5 * time.Second
	cardReportMax   = 5 * time.Minute
)

// checkA2ACards checks each a2a connection of cfg once and reports a new
// drift through reports.
func (g *Gateway) checkA2ACards(ctx context.Context, cfg *control.Config, reports cardReports) {
	for id := range reports {
		if _, ok := cfg.ByID[id]; !ok {
			delete(reports, id)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(cfg.ByID)) {
		conn := cfg.ByID[id]
		if conn.GetKind() != "a2a" || conn.GetA2A() == nil {
			continue
		}
		// A drifted connection is read again: it serves again only once its
		// card is the pinned one; its drift is reported once.
		d, err := g.engine.CheckA2ACard(ctx, conn)
		if err != nil {
			g.log.WarnContext(ctx, "gateway.a2a_card_unread", slog.String("connection_id", id), pclog.Err(err))
			continue
		}
		switch {
		case d == nil && !g.engine.A2ACardDrifted(conn):
			delete(reports, id)
		case d != nil && reports[id] == nil:
			g.log.WarnContext(ctx, "security.upstream_drift", slog.String("connection_id", id), slog.String("upstream_tool", d.Tool),
				slog.String("expected_digest", d.Expected), slog.String("observed_digest", d.Observed))
			reports[id] = &cardReport{drift: *d}
		}
	}
	g.reportA2ACards(ctx, reports, time.Now())
}

// reportA2ACards sends the drift reports not yet taken whose time came.
func (g *Gateway) reportA2ACards(ctx context.Context, reports cardReports, now time.Time) {
	for _, id := range slices.Sorted(maps.Keys(reports)) {
		r := reports[id]
		if r.sent || now.Before(r.next) {
			continue
		}
		if g.reportDrift == nil {
			r.sent = true
			continue
		}
		if err := g.reportDrift(ctx, id, r.drift); err != nil {
			r.tries++
			r.next = now.Add(min(cardReportFirst<<min(r.tries-1, 16), cardReportMax))
			g.log.ErrorContext(ctx, "gateway.drift_not_reported", slog.String("connection_id", id), slog.Int("tries", r.tries), pclog.Err(err))
			continue
		}
		r.sent = true
	}
}

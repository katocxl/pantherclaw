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
// reported.
func (g *Gateway) watchA2ACards(ctx context.Context) error {
	checked, next := int64(-1), time.Time{}
	tick := time.NewTicker(g.driftPoll)
	defer tick.Stop()
	for {
		if cfg := g.config.Current(); cfg != nil && (cfg.Version != checked || !time.Now().Before(next)) {
			g.checkA2ACards(ctx, cfg)
			checked, next = cfg.Version, time.Now().Add(g.driftEvery)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// checkA2ACards checks each a2a connection of cfg once.
func (g *Gateway) checkA2ACards(ctx context.Context, cfg *control.Config) {
	for _, id := range slices.Sorted(maps.Keys(cfg.ByID)) {
		conn := cfg.ByID[id]
		if conn.GetKind() != "a2a" || conn.GetA2A() == nil || g.engine.A2ACardDrifted(conn) {
			continue
		}
		d, err := g.engine.CheckA2ACard(ctx, conn)
		if err != nil {
			g.log.WarnContext(ctx, "gateway.a2a_card_unread", slog.String("connection_id", id), pclog.Err(err))
			continue
		}
		if d != nil {
			g.drifted(ctx, id, *d)
		}
	}
}

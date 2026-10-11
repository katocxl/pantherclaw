// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

// inventoryBatch bounds the transactions one refresh reads.
const inventoryBatch = 5000

// RefreshTraffic records, as observed channel routes, the channels and
// route modes the gateway carried in the org's transactions since the last
// refresh (F443), and returns the scopes they touched. Transactions are
// read in id order a minute behind the clock, so one still committing is
// not skipped; a route seen again only gains a sighting, keeping the mode
// last observed.
func (s *Service) RefreshTraffic(ctx context.Context, tx db.TenantTx) ([]domain.Scope, error) {
	q := dbq.New(tx)
	var after *ids.UUID
	switch w, err := q.CoverageInventoryWatermark(ctx, tx.OrgID()); {
	case err == nil:
		after = &w
	case !db.IsNoRows(err):
		return nil, err
	}
	rows, err := q.CoverageTrafficAfter(ctx, tx.OrgID(), after, inventoryBatch)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	type key struct {
		scope         domain.Scope
		channel, mode string
	}
	last := map[key]ids.UUID{}
	var order []key
	for _, r := range rows {
		if r.ConnectionID == nil || r.Channel == nil {
			continue // not through a gateway
		}
		k := key{domain.Scope{Agent: r.AgentID, Connection: *r.ConnectionID, Operation: r.Operation}, *r.Channel, r.Mode}
		if _, ok := last[k]; !ok {
			order = append(order, k)
		}
		last[k] = r.ID
	}
	var scopes []domain.Scope
	seen := map[domain.Scope]bool{}
	for _, k := range order {
		ref := last[k]
		if _, err := q.UpsertCoverageRoute(ctx, dbq.UpsertCoverageRouteParams{
			OrgID: tx.OrgID(), ID: ids.NewV7(), AgentID: &k.scope.Agent, ConnectionID: k.scope.Connection,
			Operation: &k.scope.Operation, Kind: string(domain.KindChannel), Channel: &k.channel, Observation: "observed",
			Source: "gateway", SourceRef: &ref, Mode: &k.mode, Attributes: []byte(`{}`),
		}); err != nil {
			return nil, err
		}
		if !seen[k.scope] {
			seen[k.scope] = true
			scopes = append(scopes, k.scope)
		}
	}
	return scopes, q.SetCoverageInventoryWatermark(ctx, tx.OrgID(), rows[len(rows)-1].ID)
}

// ListRoutes lists route inventory entries oldest first, the ones the
// caller may read.
func (s *Service) ListRoutes(ctx context.Context, f Filter, size int32, token string) ([]dbq.PcCoverageRoute, string, error) {
	p, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var out []dbq.PcCoverageRoute
	var next string
	err = s.read(ctx, func(ctx context.Context, r *readers) error {
		rows, err := r.q.ListCoverageRoutesPage(ctx, dbq.ListCoverageRoutesPageParams{
			OrgID: r.c.Org, ConnectionID: f.Connection, AgentID: f.Agent, After: cursor(p), MaxRows: p.Limit(),
		})
		if err != nil {
			return err
		}
		rows, next = page.Finish(p, rows, func(x dbq.PcCoverageRoute) ids.UUID { return x.ID })
		for _, row := range rows {
			if ok, err := r.can(ctx, row.AgentID); err != nil {
				return err
			} else if ok {
				out = append(out, row)
			}
		}
		return nil
	})
	return out, next, err
}

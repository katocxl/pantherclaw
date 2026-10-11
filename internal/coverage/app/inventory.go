// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/binary"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

// inventoryBatch bounds the transactions one pass reads.
const inventoryBatch = 5000

// inventoryOverlap is how far behind the watermark a refresh looks again
// for transactions that committed late: their UUIDv7 ids are older than
// ids already read. Seeing a transaction twice changes nothing (the
// upsert counts each source reference once).
const inventoryOverlap = 5 * time.Minute

// RefreshTraffic records, as observed channel routes, the channels and
// route modes the gateway carried in the org's transactions since the last
// refresh (F443), and returns the scopes they touched. Transactions are
// read in id order a minute behind the clock, and again for a few minutes
// behind the watermark, so one still committing is not skipped; from that
// overlap only a route not seen before counts. A route's first sighting
// writes a route change, so reads recompute its scope.
func (s *Service) RefreshTraffic(ctx context.Context, tx db.TenantTx) ([]domain.Scope, error) {
	q := dbq.New(tx)
	var after *ids.UUID
	switch w, err := q.CoverageInventoryWatermark(ctx, tx.OrgID()); {
	case err == nil:
		after = &w
	case !db.IsNoRows(err):
		return nil, err
	}
	var touched scopeSet
	if after != nil {
		floor := floorV7(after.Time().Add(-inventoryOverlap))
		late, err := q.CoverageTrafficAfter(ctx, dbq.CoverageTrafficAfterParams{
			OrgID: tx.OrgID(), After: &floor, Until: after, MaxRows: inventoryBatch,
		})
		if err != nil {
			return nil, err
		}
		if err := s.inventory(ctx, tx, late, true, &touched); err != nil {
			return nil, err
		}
	}
	rows, err := q.CoverageTrafficAfter(ctx, dbq.CoverageTrafficAfterParams{
		OrgID: tx.OrgID(), After: after, MaxRows: inventoryBatch,
	})
	if err != nil || len(rows) == 0 {
		return touched.list, err
	}
	if err := s.inventory(ctx, tx, rows, false, &touched); err != nil {
		return nil, err
	}
	return touched.list, q.SetCoverageInventoryWatermark(ctx, tx.OrgID(), rows[len(rows)-1].ID)
}

// scopeSet collects scopes once each, in first-seen order.
type scopeSet struct {
	list []domain.Scope
	seen map[domain.Scope]bool
}

func (s *scopeSet) add(sc domain.Scope) {
	if s.seen == nil {
		s.seen = map[domain.Scope]bool{}
	}
	if !s.seen[sc] {
		s.seen[sc] = true
		s.list = append(s.list, sc)
	}
}

// inventory upserts the channel routes of rows. With onlyNew, a scope
// counts as touched only when one of its routes is new.
func (s *Service) inventory(ctx context.Context, tx db.TenantTx, rows []dbq.CoverageTrafficAfterRow, onlyNew bool, touched *scopeSet) error {
	q := dbq.New(tx)
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
	for _, k := range order {
		ref, id := last[k], ids.NewV7()
		row, err := q.UpsertCoverageRoute(ctx, dbq.UpsertCoverageRouteParams{
			OrgID: tx.OrgID(), ID: id, AgentID: &k.scope.Agent, ConnectionID: k.scope.Connection,
			Operation: &k.scope.Operation, Kind: string(domain.KindChannel), Channel: &k.channel, Observation: "observed",
			Source: "gateway", SourceRef: &ref, Mode: &k.mode, Attributes: []byte(`{}`),
		})
		if err != nil {
			return err
		}
		if row.ID == id {
			if err := s.RecordInvalidation(ctx, tx, domain.Invalidation{
				Kind: domain.InvRoute, Connection: k.scope.Connection, Agent: &k.scope.Agent, Subject: &row.ID,
				Detail: "channel " + k.channel,
			}); err != nil {
				return err
			}
		} else if onlyNew {
			continue
		}
		touched.add(k.scope)
	}
	return nil
}

// floorV7 is the smallest UUIDv7 of the millisecond of t.
func floorV7(t time.Time) ids.UUID {
	var u ids.UUID
	var ms [8]byte
	binary.BigEndian.PutUint64(ms[:], uint64(t.UnixMilli()))
	copy(u[0:6], ms[2:8])
	u[6], u[8] = 0x70, 0x80
	return u
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

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// RefreshScanRoutes records, as observed routes of every agent of their
// connection, the routes the org-scan findings not recorded yet show
// (CoverageScanFindingsToRecord says which, and how), and returns the
// connections with a new route. A finding naming no connection of the
// org, or showing no route, is never selected, so it cannot hold back the
// findings after it. A new route writes a route change, so reads recompute
// the scopes of its connection.
func (s *Service) RefreshScanRoutes(ctx context.Context, tx db.TenantTx) ([]ids.UUID, error) {
	q := dbq.New(tx)
	rows, err := q.CoverageScanFindingsToRecord(ctx, tx.OrgID())
	if err != nil {
		return nil, err
	}
	touched := map[ids.UUID]bool{}
	var out []ids.UUID
	for _, r := range rows {
		ref, id, locator := r.ID, ids.NewV7(), r.Locator
		row, err := q.UpsertCoverageRoute(ctx, dbq.UpsertCoverageRouteParams{
			OrgID: tx.OrgID(), ID: id, ConnectionID: r.ConnectionID, Kind: r.Kind, Locator: &locator,
			Observation: "observed", Source: "scan", SourceRef: &ref, Attributes: []byte(`{}`),
		})
		if err != nil {
			return nil, err
		}
		if row.ID != id {
			continue // a route another finding already showed
		}
		if err := s.RecordInvalidation(ctx, tx, domain.Invalidation{
			Kind: domain.InvRoute, Connection: r.ConnectionID, Subject: &row.ID, Detail: r.Kind + " from the org scan",
		}); err != nil {
			return nil, err
		}
		if !touched[r.ConnectionID] {
			touched[r.ConnectionID] = true
			out = append(out, r.ConnectionID)
		}
	}
	return out, nil
}

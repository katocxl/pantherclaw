// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// RouteStateForAutomationTx reads one scope's coverage as GetCoverage reads
// it, in the caller's transaction and without a viewer: a governed
// automation's wait_coverage step (G0 M11 part 2 D31) waits on the
// trigger's own route and sees nothing else. It returns the state's name
// and the current snapshot (zero when the scope was never assessed).
func (s *Service) RouteStateForAutomationTx(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent, connection ids.UUID, operation string) (string, ids.UUID, error) {
	ttx, err := db.AdoptTenantTx(ctx, tx, org)
	if err != nil {
		return "", ids.UUID{}, err
	}
	sc := domain.Scope{Agent: agent, Connection: connection, Operation: operation}
	row, err := dbq.New(ttx).CurrentCoverageSnapshot(ctx, dbq.CurrentCoverageSnapshotParams{
		OrgID: org, AgentID: agent, ConnectionID: connection, Operation: operation,
	})
	var cur *dbq.PcCoverageSnapshot
	if err == nil {
		cur = &row
	} else if !db.IsNoRows(err) {
		return "", ids.UUID{}, err
	}
	r, err := s.record(ctx, ttx, sc, cur, true, packages{}, s.now())
	if err != nil {
		return "", ids.UUID{}, err
	}
	var snap ids.UUID
	if r.Snapshot != nil {
		snap = r.Snapshot.ID
	}
	return r.State.String(), snap, nil
}

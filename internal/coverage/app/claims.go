// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Claim is the coverage claim of a decision receipt (HR-217): the scope's
// snapshot that was current at decision time, with its state and
// exclusions, and the state effective then. That is the snapshot's while
// it held; once it lapsed, the scope recomputed from current evidence and
// capped at PARTIAL, with the reason ("expired" or the kind of the change
// it did not see). A claim is never stronger than its snapshot.
type Claim struct {
	Scope         domain.Scope
	State         domain.State
	Snapshot      ids.UUID
	SnapshotState domain.State
	Lapsed        bool
	Reason        string
	Exclusions    []ids.UUID
	ExpiresAt     *time.Time
}

// ClaimAt returns the coverage claim of a scope at time at, or nil when the
// scope was never assessed. It reads in its own read-only transaction.
func (s *Service) ClaimAt(ctx context.Context, org ids.OrgID, sc domain.Scope, at time.Time) (*Claim, error) {
	var out *Claim
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).CurrentCoverageSnapshot(ctx, dbq.CurrentCoverageSnapshotParams{
			OrgID: org, AgentID: sc.Agent, ConnectionID: sc.Connection, Operation: sc.Operation,
		})
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		r, err := s.record(ctx, tx, sc, &row, false, packages{}, at)
		if err != nil {
			return err
		}
		out = &Claim{
			Scope: sc, State: r.State, Snapshot: row.ID, SnapshotState: r.Computed, Lapsed: r.Recomputed != nil,
			Exclusions: r.Body.Exclusions, ExpiresAt: row.ExpiresAt,
		}
		if out.Lapsed {
			out.Reason = r.Lapse
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

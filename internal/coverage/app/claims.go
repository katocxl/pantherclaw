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
// snapshot that was current at decision time, by id and the SHA-256 of its
// ledger body, and its state as it read then, downgraded when it lapsed or
// a change followed it. A claim is never stronger than its snapshot.
type Claim struct {
	State    domain.State
	Snapshot ids.UUID
	Digest   []byte
}

// ClaimAt returns the coverage claim of a scope at time at, or nil when the
// scope was never assessed. It reads in its own read-only transaction.
func (s *Service) ClaimAt(ctx context.Context, org ids.OrgID, sc domain.Scope, at time.Time) (*Claim, error) {
	var out *Claim
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).CoverageClaim(ctx, dbq.CoverageClaimParams{
			OrgID: org, AgentID: sc.Agent, ConnectionID: sc.Connection, Operation: sc.Operation,
		})
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		state, ok := domain.ParseState(row.State)
		if !ok {
			return nil
		}
		changes := 0
		if row.Changed {
			changes = 1
		}
		state, _ = domain.ReadAt(state, row.ExpiresAt, changes, at)
		out = &Claim{State: state, Snapshot: row.ID, Digest: row.BodySha256}
		return nil
	}, db.ReadOnly())
	return out, err
}

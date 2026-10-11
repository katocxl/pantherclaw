// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// claimTimeout bounds the coverage read on the decision path: a slow read
// drops the claim, never the decision (G0 M9 decision 3).
const claimTimeout = 50 * time.Millisecond

// CoverageClaim is a decision receipt's coverage claim (G0 M9, HR-217,
// PAP-1 §9.1): the coverage snapshot that was current for the action's
// scope at decision time, its state and exclusions, and the state effective
// then. When the snapshot had lapsed, lapsed is true, reason says why
// ("expired" or the invalidation kind) and state is the scope recomputed
// at decision time, capped at PARTIAL. pclaw verify and evidence packs
// check it against the snapshot ledger.
type CoverageClaim struct {
	V             int                `json:"v"`
	State         string             `json:"state"`
	Snapshot      string             `json:"snapshot"`
	Scope         CoverageClaimScope `json:"scope"`
	SnapshotState string             `json:"snapshot_state"`
	Lapsed        bool               `json:"lapsed"`
	Reason        string             `json:"reason,omitzero"`
	Exclusions    []string           `json:"exclusions"`
	ExpiresAt     string             `json:"expires_at,omitzero"`
}

// CoverageClaimScope is the scope a claim is about.
type CoverageClaimScope struct {
	Agent      string `json:"agent"`
	Connection string `json:"connection"`
	Operation  string `json:"operation"`
}

// CoverageClaimer returns the coverage claim of a scope at time at; nil
// when the scope was never assessed.
type CoverageClaimer interface {
	CoverageClaim(ctx context.Context, org ids.OrgID, agent, connection ids.UUID, operation string, at time.Time) (*CoverageClaim, error)
}

// coverageClaim is the claim of ev's scope, or nil: without a claimer or
// a connection, or when the claim cannot be read within claimTimeout (no
// claim is never a stronger statement than a claim, so a failed read only
// drops it, and the drop is logged).
func (a *Authority) coverageClaim(ctx context.Context, org ids.OrgID, ev *pipeline.Evaluation) *CoverageClaim {
	if a.Coverage == nil || ev.Connection == nil {
		return nil
	}
	agent, err := ids.ParseUUID(ev.Identity.Agent)
	if err != nil {
		return nil
	}
	read, cancel := context.WithTimeout(ctx, claimTimeout)
	defer cancel()
	claim, err := a.Coverage.CoverageClaim(read, org, agent, ev.Connection.ID, ev.Operation, ev.Now)
	if err != nil {
		cause := "error"
		if errors.Is(err, context.DeadlineExceeded) {
			cause = "timeout"
		}
		a.log(ctx).WarnContext(ctx, "coverage.claim_dropped", slog.String("connection_id", ev.Connection.ID.String()),
			slog.String("operation", ev.Operation), slog.String("cause", cause), pclog.Err(err))
		return nil
	}
	return claim
}

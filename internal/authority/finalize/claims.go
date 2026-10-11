// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize

import (
	"context"
	"log/slog"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// CoverageClaim is a decision receipt's coverage claim (G0 M9, HR-217):
// the coverage snapshot that was current for the action's scope (agent,
// connection, operation) at decision time, by id and the digest of its
// ledger body, and its state as it read then. pclaw verify and evidence
// packs check it against the snapshot's ledger entry: the scope matches,
// the state is never stronger than the snapshot's, and an ENFORCED claim
// is inside the snapshot's validity.
type CoverageClaim struct {
	State      string `json:"state"`
	Snapshot   string `json:"snapshot"`
	Digest     string `json:"digest"`
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
// a connection, or when the claim cannot be read (no claim is never a
// stronger statement than a claim, so a failed read only drops it).
func (a *Authority) coverageClaim(ctx context.Context, org ids.OrgID, ev *pipeline.Evaluation) *CoverageClaim {
	if a.Coverage == nil || ev.Connection == nil {
		return nil
	}
	agent, err := ids.ParseUUID(ev.Identity.Agent)
	if err != nil {
		return nil
	}
	claim, err := a.Coverage.CoverageClaim(ctx, org, agent, ev.Connection.ID, ev.Operation, ev.Now)
	if err != nil {
		a.log(ctx).WarnContext(ctx, "coverage.claim_unavailable", slog.String("connection_id", ev.Connection.ID.String()), pclog.Err(err))
		return nil
	}
	return claim
}

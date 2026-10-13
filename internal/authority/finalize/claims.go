// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// DefaultClaimTimeout bounds the coverage read on the decision path when
// Authority.ClaimTimeout is unset: a slow read makes the claim unavailable,
// never fails the decision (G0 M9 decision 3).
const DefaultClaimTimeout = 50 * time.Millisecond

// Why a receipt's coverage claim is unavailable.
const (
	ClaimTimeout = "timeout"
	ClaimError   = "error"
)

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
	// Unavailable is set, alone, when the claim could not be read within
	// the claim timeout (ClaimTimeout) or its read failed (ClaimError): the
	// receipt says so instead of leaving the claim out, and verifiers report
	// it as unavailable, never as a state.
	Unavailable string `json:"unavailable,omitzero"`
}

// MarshalJSONTo writes an unavailable claim as {"unavailable": reason}
// alone, and any other claim with all its fields.
func (c CoverageClaim) MarshalJSONTo(enc *jsontext.Encoder) error {
	if c.Unavailable != "" {
		return json.MarshalEncode(enc, struct {
			Unavailable string `json:"unavailable"`
		}{c.Unavailable})
	}
	type plain CoverageClaim
	return json.MarshalEncode(enc, plain(c))
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

// coverageClaim is the claim of ev's scope: nil without a claimer or a
// connection, or when the scope was never assessed. A read that fails or
// takes longer than the claim timeout gives an unavailable claim, and is
// logged, so a receipt never drops its claim silently.
func (a *Authority) coverageClaim(ctx context.Context, org ids.OrgID, ev *pipeline.Evaluation) *CoverageClaim {
	if a.Coverage == nil || ev.Connection == nil {
		return nil
	}
	agent, err := ids.ParseUUID(ev.Identity.Agent)
	if err != nil {
		return nil
	}
	timeout := a.ClaimTimeout
	if timeout <= 0 {
		timeout = DefaultClaimTimeout
	}
	read, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	claim, err := a.Coverage.CoverageClaim(read, org, agent, ev.Connection.ID, ev.Operation, ev.Now)
	if err != nil {
		cause := ClaimError
		if errors.Is(err, context.DeadlineExceeded) {
			cause = ClaimTimeout
		}
		a.log(ctx).WarnContext(ctx, "coverage.claim_unavailable", slog.String("connection_id", ev.Connection.ID.String()),
			slog.String("operation", ev.Operation), slog.String("cause", cause), pclog.Err(err))
		return &CoverageClaim{Unavailable: cause}
	}
	return claim
}

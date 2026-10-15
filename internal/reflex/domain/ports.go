// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// The ports take a pgx.Tx (G0 M10 D1): the one place a domain package of
// this repository imports pgx, kept to this file (.golangci.yml depguard
// domain-is-pure exempts it). Implementers turn it back into a tenant
// transaction with db.AdoptTenantTx.

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Raiser records signals (core, D14): an alert, a live ledger entry or
// nothing, by attention, in the caller's transaction. It returns the alert
// id, or the zero id when no alert was written.
type Raiser interface {
	Raise(ctx context.Context, tx pgx.Tx, s Signal) (ids.UUID, error)
}

// CaseSeed is what a new case starts from (cases, D19).
type CaseSeed struct {
	Org        ids.OrgID
	Title      string
	Source     string
	Subjects   []Subject
	Evidence   []EvidenceRef
	Questions  []string
	AlertID    *ids.UUID
	IncidentID *ids.UUID
	Opener     Subject
}

// CaseOpener opens a case (cases, D19).
type CaseOpener interface {
	Open(ctx context.Context, tx pgx.Tx, seed CaseSeed) (ids.UUID, error)
}

// Failure is an owned operational failure (F641): what broke, where, who
// owns it, by when and what to do next.
type Failure struct {
	Org       ids.OrgID
	Kind      string
	Summary   string
	NextStep  string
	Scope     []Subject
	Owner     *Subject
	Deadline  time.Time
	DedupeKey string
}

// FailureSink records owned failures (core, D18). A repeat with the same
// dedupe key while the failure is open returns the open failure.
type FailureSink interface {
	Report(ctx context.Context, tx pgx.Tx, f Failure) (ids.UUID, error)
}

// Containment controls (response, D21).
const (
	ControlDenyAll       = "DENY_ALL"
	ControlHoldWrites    = "HOLD_WRITES"
	ControlDenyOperation = "DENY_OPERATION"
)

// ContainRequest asks for one containment control (response, D21).
type ContainRequest struct {
	Org        ids.OrgID
	Scope      Subject
	Control    string
	Operation  string
	Reason     string
	CaseID     *ids.UUID
	IncidentID *ids.UUID
	Actor      Subject
	// PreviewDigest is the SHA-256 of the canonical preview a wider control
	// was confirmed against (D23).
	PreviewDigest []byte
	Idempotency   string
}

// ContainResult is the response action a request created and its status
// (REQUESTED|PARTIAL|CONFIRMED|FAILED|UNSUPPORTED).
type ContainResult struct {
	ActionID ids.UUID
	Status   string
}

// Container applies containment controls (response, D21).
type Container interface {
	Contain(ctx context.Context, tx pgx.Tx, r ContainRequest) (ContainResult, error)
}

// ReductionChange is an authority reduction to preview (exposure, D27):
// containing, revoking or narrowing the listed subjects.
type ReductionChange struct {
	// Kind is what the change does, for example "contain", "revoke_grant"
	// or "narrow_grant".
	Kind      string
	Subjects  []Subject
	Control   string
	Operation string
}

// Reach is how much one side of a preview can reach.
type Reach struct {
	// Resources counts reachable resource groups; Usable, Conditional and
	// Uncertain split the rights by label (D27).
	Resources   int
	Usable      int
	Conditional int
	Uncertain   int
}

// ReachDiff is the before and after of a reduction and what it would
// disrupt (F259).
type ReachDiff struct {
	Before, After Reach
	// Disruption lists the runs, agents or workloads the change would stop.
	Disruption []Subject
	// Stale marks a diff computed from a snapshot older than the last
	// relevant change.
	Stale bool
	Note  string
}

// ReachPreviewer previews an authority reduction (exposure, D27).
type ReachPreviewer interface {
	PreviewReduction(ctx context.Context, org ids.OrgID, c ReductionChange) (ReachDiff, error)
}

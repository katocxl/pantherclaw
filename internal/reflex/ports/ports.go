// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ports holds the Reflex ports that run inside the caller's
// transaction (G0 M10 D1, D55): Raiser, CaseOpener, FailureSink and
// Container. They take a pgx.Tx, so they live outside the pure domain
// package; their value types (Signal, CaseSeed, Failure, ContainRequest,
// ContainResult) stay in reflexdomain. Implementers turn the pgx.Tx back
// into a tenant transaction with db.AdoptTenantTx. Every implementer is
// wired in internal/server; packages never import each other's adapters.
//
// Import it as reflexports.
package ports

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Raiser records signals (core, D14): an alert, a live ledger entry or
// nothing, by attention, in the caller's transaction. It returns the alert
// id, or the zero id when no alert was written.
type Raiser interface {
	Raise(ctx context.Context, tx pgx.Tx, s reflexdomain.Signal) (ids.UUID, error)
}

// CaseOpener opens a case (cases, D19).
type CaseOpener interface {
	Open(ctx context.Context, tx pgx.Tx, seed reflexdomain.CaseSeed) (ids.UUID, error)
}

// FailureSink records owned failures (core, D18). A repeat with the same
// dedupe key while the failure is open returns the open failure.
type FailureSink interface {
	Report(ctx context.Context, tx pgx.Tx, f reflexdomain.Failure) (ids.UUID, error)
}

// Container applies containment controls (response, D21).
type Container interface {
	Contain(ctx context.Context, tx pgx.Tx, r reflexdomain.ContainRequest) (reflexdomain.ContainResult, error)
}

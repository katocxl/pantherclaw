// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/grants/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ErrNotPromoted refuses a new, widened or delegated PRODUCTION grant
// whose operations the agent is not promoted for (G0 M11 part 2 D39,
// HR-290).
var ErrNotPromoted = pcerr.New(pcerr.FailedPrecondition, "NOT_PROMOTED",
	"the agent is not promoted for every operation of this grant in this environment")

// errNoGate refuses a production grant when no promotion gate is wired
// (D105): the gate fails closed.
var errNoGate = pcerr.Wrap(ErrNotPromoted, pcerr.FailedPrecondition, "NOT_PROMOTED",
	"no production promotion gate is configured: production grants are refused")

// PromotionGate is the production promotion gate (G0 M11 part 2 D11, D39,
// D80, D93, F6, F7). Issue, a widening Revise, Delegate and automation
// issuance call it once, in their transaction, when the grant's
// environment is a PRODUCTION one; ops are the grant's operations as
// listed (nil when the grant lists none, which never passes). It returns
// ErrNotPromoted (wrapped with the operations) when an operation lacks an
// ACTIVE or unexpired PROVISIONAL promotion. Otherwise until is the
// earliest expiry of the PROVISIONAL promotions the grant stands on, read
// from the same rows (nil: none), and the caller caps the grant's expiry
// at it (CapExpiry): a grant under a provisional promotion ends with it.
type PromotionGate interface {
	Check(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent, env ids.UUID, ops domain.Ops) (until *time.Time, err error)
}

// CapExpiry ends g no later than until (D80). It reports whether it
// shortened g.
func CapExpiry(g *domain.Grant, until *time.Time) bool {
	if until == nil || (!g.ExpiresAt.IsZero() && !g.ExpiresAt.After(*until)) {
		return false
	}
	g.ExpiresAt = *until
	return true
}

// gateOps are the operations a grant lists, nil when it lists none.
func gateOps(b domain.Bounds) domain.Ops {
	if b.Operations == nil {
		return nil
	}
	return *b.Operations
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/grants/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ErrNotPromoted refuses a new or widened PRODUCTION grant whose
// operations the agent is not promoted for (G0 M11 part 2 D39, HR-290).
var ErrNotPromoted = pcerr.New(pcerr.FailedPrecondition, "NOT_PROMOTED",
	"the agent is not promoted for every operation of this grant in this environment")

// PromotionGate is the production promotion gate (G0 M11 part 2 D11, D39,
// F6). Issue, a widening Revise and automation issuance call it in their
// transaction when the grant's environment is a PRODUCTION one; ops are the
// grant's operations as listed (nil when the grant lists none, which never
// passes). It returns ErrNotPromoted (wrapped with the operations) when an
// operation lacks an ACTIVE promotion. The govern stream implements it; a
// nil gate checks nothing until it is wired.
type PromotionGate interface {
	Check(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent, env ids.UUID, ops domain.Ops) error
}

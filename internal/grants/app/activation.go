// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"fmt"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ReasonPackageLimitNeverCounts refuses a package activation after which a
// live grant's or guardrail's budget or counter would never count.
const ReasonPackageLimitNeverCounts = "PACKAGE_LIMIT_NEVER_COUNTS"

// StoredLimits are the limits of one grant or guardrail at its current
// revision.
type StoredLimits struct {
	// Kind is "grant" or "guardrail".
	Kind   string
	ID     ids.UUID
	Limits domain.Limits
}

// LiveLimitsTx reads, in tx, the limits of the org's active, unexpired
// grants and of its guardrails that set any.
type LiveLimitsTx interface {
	LiveLimitsInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID) ([]StoredLimits, error)
}

// ActivationCheck re-checks the budgets and counters of live grants and
// guardrails when a package version is activated (G0 M8, HR-206). A limit
// set before its package was installed was accepted, since its operation
// had no definition; if the activated version defines that operation as
// only ever a consequence, the limit would never count anything, a silent
// fail-open. The activation is refused instead, naming the grant or
// guardrail to change first.
type ActivationCheck struct {
	Limits LiveLimitsTx
}

// CheckActivation implements definitions/app.ActivationCheck.
func (a ActivationCheck) CheckActivation(ctx context.Context, tx db.TenantTx, active []*defs.Definition) error {
	byOp := make(map[string]*defs.Definition, len(active))
	for _, d := range active {
		byOp[d.Operation] = d
	}
	lookup := func(op string) *defs.Definition { return byOp[op] }
	stored, err := a.Limits.LiveLimitsInTx(ctx, tx, tx.OrgID())
	if err != nil {
		return err
	}
	for _, s := range stored {
		if err := s.Limits.CheckDispatched(lookup); err != nil {
			return pcerr.Wrap(err, pcerr.FailedPrecondition, ReasonPackageLimitNeverCounts,
				fmt.Sprintf("with this version active, %s %s would never count: %v; change its limits first", s.Kind, s.ID, err))
		}
	}
	return nil
}

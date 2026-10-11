// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Protection is what an agent's coverage records say about it (F021):
// PROTECTED only when every scope that counts is ENFORCED now, OBSERVED
// when none is, PARTIALLY_PROTECTED for a mix. A scope a person excluded
// as a whole does not count (HR-212); an agent with no scope that counts
// is OBSERVED.
func Protection(states []domain.State, excluded []bool) adomain.State {
	enforced, counted := 0, 0
	for i, s := range states {
		if excluded[i] {
			continue
		}
		counted++
		if s == domain.Enforced {
			enforced++
		}
	}
	if enforced == 0 {
		return adomain.StateObserved
	}
	if enforced == counted {
		return adomain.StateProtected
	}
	return adomain.StatePartiallyProtected
}

// deriveLifecycle moves the agent among OBSERVED, PARTIALLY_PROTECTED and
// PROTECTED from its current coverage records as they read at now, in tx.
func deriveLifecycle(ctx context.Context, tx db.TenantTx, agent ids.UUID, now time.Time) error {
	q := dbq.New(tx)
	rows, err := q.CurrentCoverageOfAgent(ctx, tx.OrgID(), agent)
	if err != nil {
		return err
	}
	states := make([]domain.State, len(rows))
	excluded := make([]bool, len(rows))
	for i, r := range rows {
		s, _ := domain.ParseState(r.State)
		changes := 0
		if r.Changed {
			changes = 1
		}
		states[i], _ = domain.ReadAt(s, r.ExpiresAt, changes, now)
		excluded[i] = r.Excluded
	}
	return agents.MarkProtection(ctx, q, tx.OrgID(), agent, Protection(states, excluded), adomain.System)
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package promotions

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	coverage "github.com/katocxl/pantherclaw/internal/coverage/app"
	cdomain "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// coverage is checked per serving connection (D80, D93 V4): the agent's
// connections whose packages declare the operation. Any coverage record
// of the operation that is not ENFORCED or PARTIAL, or has lapsed, fails
// it; a passing record on every serving connection passes it; otherwise
// (a serving connection without a record yet, or none serving it) it is
// pending, so the operation is promotable provisionally. Every current
// record of the agent and operation is read: no row cap can drop one.
func (s *subject) coverage(ctx context.Context, q *dbq.Queries, op string, now time.Time) (Check, error) {
	rows, err := q.PromotionCoverageSnapshots(ctx, s.org, s.row.ID, op)
	if err != nil {
		return Check{}, err
	}
	var bad []string
	var passing []ids.UUID
	for _, row := range rows {
		st, _ := cdomain.ParseState(row.State)
		if st != cdomain.Enforced && st != cdomain.Partial {
			bad = append(bad, fmt.Sprintf("%s on connection %s is %s", row.Operation, row.ConnectionID, row.State))
			continue
		}
		lapse, err := coverage.Lapsed(ctx, q, row, now)
		if err != nil {
			return Check{}, err
		}
		if lapse != "" {
			bad = append(bad, fmt.Sprintf("%s on connection %s lapsed (%s)", row.Operation, row.ConnectionID, lapse))
			continue
		}
		passing = append(passing, row.ConnectionID)
	}
	if len(bad) > 0 {
		return Check{Name: CheckCoverage, Detail: clip(strings.Join(bad, "; "))}, nil
	}
	serving := s.catalog.serving[op]
	var without []string
	for _, c := range serving {
		if !slices.Contains(passing, c) {
			without = append(without, c.String())
		}
	}
	switch {
	case len(serving) == 0:
		// Not a failing record: promotable provisionally (D80).
		return Check{Name: CheckCoverage, Pending: true, Detail: "no coverage record yet: none of the agent's connections serves " + op + " so far"}, nil
	case len(without) > 0:
		return Check{Name: CheckCoverage, Pending: true, Detail: clip("no coverage record yet of " + op + " on connection " + strings.Join(without, ", "))}, nil
	}
	return Check{Name: CheckCoverage, Passed: true, Detail: fmt.Sprintf("%d serving connection(s) ENFORCED or PARTIAL", len(serving))}, nil
}

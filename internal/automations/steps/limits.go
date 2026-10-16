// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package steps

import (
	"slices"

	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// launchLimits are the limits of a launch's grant (D9, D84 E7): the
// ceiling's per-grant limits, or a launch's own limits that only narrow
// them. Every per-grant rule must be kept (same id, grouping, operations,
// currency, key and period) with a limit no larger; a launch may add
// rules. It reports false when want would widen per-grant.
func launchLimits(perGrant gdomain.Limits, want *gdomain.Limits) (gdomain.Limits, bool) {
	if want == nil {
		return perGrant, true
	}
	for _, p := range perGrant.Budgets {
		i := slices.IndexFunc(want.Budgets, func(b gdomain.BudgetRule) bool { return b.ID == p.ID })
		if i < 0 {
			return gdomain.Limits{}, false
		}
		w := want.Budgets[i]
		if w.Grouping != p.Grouping || !slices.Equal(w.Operations, p.Operations) || w.Currency != p.Currency ||
			w.Period != p.Period || !notAbove(w.Limit, p.Limit) || !notAbove(w.MaxCount, p.MaxCount) {
			return gdomain.Limits{}, false
		}
	}
	for _, p := range perGrant.Counters {
		i := slices.IndexFunc(want.Counters, func(c gdomain.CountRule) bool { return c.ID == p.ID })
		if i < 0 {
			return gdomain.Limits{}, false
		}
		w := want.Counters[i]
		if !slices.Equal(w.Operations, p.Operations) || w.Key != p.Key || w.Window != p.Window ||
			!notAbove(w.Max, p.Max) || !notAbove(w.MaxOutstanding, p.MaxOutstanding) {
			return gdomain.Limits{}, false
		}
	}
	return *want, true
}

// notAbove reports whether a limit w stays within p: an unset p bounds
// nothing; a set p needs a set w no larger.
func notAbove(w, p string) bool {
	if p == "" {
		return true
	}
	if w == "" {
		return false
	}
	a, err := money.Parse(w)
	if err != nil {
		return false
	}
	b, err := money.Parse(p)
	return err == nil && a.Cmp(b) <= 0
}

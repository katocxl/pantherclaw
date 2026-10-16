// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"

	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// NarrowLimits applies narrow to base, rule by rule: each rule of narrow
// replaces base's rule with the same id and may only lower its numbers.
// A rule base does not have, a reshaped rule (operations, grouping,
// currency, period, key or window) or a higher number is ErrOutside. Rules
// narrow leaves out keep base's values, so the result is never wider than
// base (an automation's launch under its ceiling's per-grant limits, D84).
func NarrowLimits(base, narrow Limits) (Limits, error) {
	out := Limits{Budgets: slices.Clone(base.Budgets), Counters: slices.Clone(base.Counters)}
	for _, r := range narrow.Budgets {
		i := slices.IndexFunc(out.Budgets, func(b BudgetRule) bool { return b.ID == r.ID })
		if i < 0 {
			return Limits{}, outside("budget %q is not one of the per-grant budgets", r.ID)
		}
		b := out.Budgets[i]
		shape := b
		shape.Limit, shape.MaxCount = r.Limit, r.MaxCount
		if !slicesContainsJSON([]BudgetRule{shape}, r) {
			return Limits{}, outside("budget %q changes more than its limit or count", r.ID)
		}
		if !decimalAtMost(r.Limit, b.Limit) || !countAtMost(r.MaxCount, b.MaxCount) {
			return Limits{}, outside("budget %q is higher than the per-grant budget", r.ID)
		}
		out.Budgets[i] = r
	}
	for _, r := range narrow.Counters {
		i := slices.IndexFunc(out.Counters, func(c CountRule) bool { return c.ID == r.ID })
		if i < 0 {
			return Limits{}, outside("counter %q is not one of the per-grant counters", r.ID)
		}
		c := out.Counters[i]
		shape := c
		shape.Max, shape.MaxOutstanding = r.Max, r.MaxOutstanding
		if !slicesContainsJSON([]CountRule{shape}, r) {
			return Limits{}, outside("counter %q changes more than its maximum", r.ID)
		}
		if !countAtMost(r.Max, c.Max) || !countAtMost(r.MaxOutstanding, c.MaxOutstanding) {
			return Limits{}, outside("counter %q is higher than the per-grant counter", r.ID)
		}
		out.Counters[i] = r
	}
	return out, nil
}

// CoversBudget reports whether a budget rule of l with an amount limit
// covers op.
func (l Limits) CoversBudget(op string) bool {
	for _, b := range l.Budgets {
		if b.Limit == "" || b.Currency == "" {
			continue
		}
		if _, ok := (Ops{op}).Within(b.Operations); ok {
			return true
		}
	}
	return false
}

// decimalAtMost: an unset base allows any value; an unset next widens a
// set base.
func decimalAtMost(next, base string) bool {
	if base == "" {
		return true
	}
	if next == "" {
		return false
	}
	n, err1 := money.Parse(next)
	b, err2 := money.Parse(base)
	return err1 == nil && err2 == nil && n.Cmp(b) <= 0
}

func countAtMost(next, base string) bool {
	if base == "" {
		return true
	}
	if next == "" {
		return false
	}
	n, err1 := parseCount("limit", next)
	b, err2 := parseCount("limit", base)
	return err1 == nil && err2 == nil && n <= b
}

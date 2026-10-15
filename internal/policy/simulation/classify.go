// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package simulation

import adomain "github.com/katocxl/pantherclaw/internal/authority/domain"

// Category is what a policy version changes about one recorded decision
// (G0 M11.1 D5).
//
// Stand-in: this file copies D5's replay.Classify (signature and
// semantics) until it is on this branch's base; then the simulation uses
// replay.Classify and this file goes.
type Category string

// Categories (D5). Unevaluable is set by the caller for a replay that is
// not reproduced or incomplete.
const (
	Unchanged        Category = "UNCHANGED"
	NewlyDenied      Category = "NEWLY_DENIED"
	NewlyHeld        Category = "NEWLY_HELD"
	NewlyConstrained Category = "NEWLY_CONSTRAINED"
	NewlyAllowed     Category = "NEWLY_ALLOWED"
	ReasonChanged    Category = "REASON_CHANGED"
	Unevaluable      Category = "UNEVALUABLE"
)

// Categories lists every category, in report order.
func Categories() []Category {
	return []Category{NewlyDenied, NewlyHeld, NewlyConstrained, NewlyAllowed, ReasonChanged, Unevaluable, Unchanged}
}

// Valid reports whether c is a category.
func (c Category) Valid() bool {
	for _, x := range Categories() {
		if x == c {
			return true
		}
	}
	return false
}

// severity orders decisions (D5): DENY and CANNOT_AUTHORIZE are equally
// strict.
func severity(d adomain.Decision) int {
	switch d {
	case adomain.Allow:
		return 0
	case adomain.AllowWithObligations:
		return 1
	case adomain.RequireStepUp:
		return 2
	case adomain.RequireApproval:
		return 3
	default: // DENY, CANNOT_AUTHORIZE and anything unknown: the strictest
		return 4
	}
}

// Classify says what changed from before to after (D5): the same decision
// and reason are unchanged; a stricter decision is newly denied, held or
// constrained by what it became; a less strict one is newly allowed
// (expanded exposure, F189); as strict with another decision or reason is
// a changed reason.
func Classify(before, after adomain.Decision, beforeReason, afterReason string) Category {
	b, a := severity(before), severity(after)
	switch {
	case before == after && beforeReason == afterReason:
		return Unchanged
	case a > b && a == 4:
		return NewlyDenied
	case a > b && a >= 2:
		return NewlyHeld
	case a > b:
		return NewlyConstrained
	case a < b:
		return NewlyAllowed
	default:
		return ReasonChanged
	}
}

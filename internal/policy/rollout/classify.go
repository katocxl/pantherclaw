// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rollout

import adomain "github.com/katocxl/pantherclaw/internal/authority/domain"

// Category is how a shadow evaluation's decision differs from the recorded
// one (D5).
//
// Stand-in: this file copies coordinator decision D5 until S1a's
// replay.Classify (internal/authority/replay/classify.go) is merged; the
// merge deletes it and the sweeper calls replay.Classify.
type Category string

// Categories (D5).
const (
	Unchanged        Category = "UNCHANGED"
	NewlyDenied      Category = "NEWLY_DENIED"
	NewlyHeld        Category = "NEWLY_HELD"
	NewlyConstrained Category = "NEWLY_CONSTRAINED"
	NewlyAllowed     Category = "NEWLY_ALLOWED"
	ReasonChanged    Category = "REASON_CHANGED"
	Unevaluable      Category = "UNEVALUABLE"
)

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
	case adomain.Deny, adomain.CannotAuthorize:
		return 4
	}
	return 4
}

// Classify compares a decision and its decisive reason before and after
// (D5).
func Classify(before, after adomain.Decision, beforeReason, afterReason string) Category {
	b, a := severity(before), severity(after)
	switch {
	case before == after && beforeReason == afterReason:
		return Unchanged
	case a > b && (after == adomain.Deny || after == adomain.CannotAuthorize):
		return NewlyDenied
	case a > b && (after == adomain.RequireStepUp || after == adomain.RequireApproval):
		return NewlyHeld
	case a > b:
		return NewlyConstrained
	case a < b:
		return NewlyAllowed
	}
	return ReasonChanged
}

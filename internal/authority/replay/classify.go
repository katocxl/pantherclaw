// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package replay

import adomain "github.com/katocxl/pantherclaw/internal/authority/domain"

// Category is how a decision changes when the same action is decided under
// another policy version (M11.1 D5; simulation F187–F190 and shadow F200).
type Category string

// Categories. UNEVALUABLE is never returned by Classify: callers set it
// when a replay was not reproduced or is incomplete.
const (
	Unchanged        Category = "UNCHANGED"
	NewlyDenied      Category = "NEWLY_DENIED"
	NewlyHeld        Category = "NEWLY_HELD"
	NewlyConstrained Category = "NEWLY_CONSTRAINED"
	NewlyAllowed     Category = "NEWLY_ALLOWED"
	ReasonChanged    Category = "REASON_CHANGED"
	Unevaluable      Category = "UNEVALUABLE"
)

// severityDeny is the severity of DENY and CANNOT_AUTHORIZE.
const severityDeny = 4

// severity orders decisions by how much they restrict the action. An
// unknown decision ranks with DENY, so it is never read as an allow.
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
		return severityDeny
	default:
		return severityDeny
	}
}

// Classify compares a decision and its decisive reason before and after.
// A lower severity after is NEWLY_ALLOWED: expanded exposure (F189), even
// when the action is still held at a lower level.
func Classify(before, after adomain.Decision, beforeReason, afterReason string) Category {
	sb, sa := severity(before), severity(after)
	switch {
	case before == after && beforeReason == afterReason:
		return Unchanged
	case sa > sb && sa == severityDeny:
		return NewlyDenied
	case sa > sb && sa >= severity(adomain.RequireStepUp):
		return NewlyHeld
	case sa > sb:
		return NewlyConstrained
	case sa < sb:
		return NewlyAllowed
	default:
		return ReasonChanged
	}
}

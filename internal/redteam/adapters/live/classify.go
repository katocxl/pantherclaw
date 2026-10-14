// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package live

import (
	"slices"

	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// facts are what a gateway face says about one call, whichever face it was.
type facts struct {
	// Class is the gateway's error_class; empty for an allowed call.
	Class string
	// Code is the decisive reason or the gateway's own refusal code.
	Code string
	// Decision is the Authority's decision when the face reports one.
	Decision string
	Reasons  []string
	// Held marks a held call.
	Held          bool
	TransactionID string
}

// classify turns a gateway answer into a range outcome (D10): an allowed
// call is ALLOW, a held one HOLD, an Authority DENY or CANNOT_AUTHORIZE keep
// their names, a refusal the gateway made itself (no decision) is REFUSED
// with its code, and a target's refusal is TARGET_REFUSED.
func classify(f facts) domain.Observation {
	o := domain.Observation{TransactionID: f.TransactionID, Reasons: slices.Clone(f.Reasons)}
	switch {
	case f.Held || f.Class == "held":
		o.Outcome, o.Reason = domain.OutcomeHold, firstOf(f.Reasons, f.Code)
	case f.Class == "":
		o.Outcome = domain.OutcomeAllow
	case f.Class == "policy_denied":
		o.Outcome, o.Reason = domain.OutcomeDeny, firstOf(f.Reasons, f.Code)
	case f.Class == "cannot_authorize" && (f.Decision != "" || len(f.Reasons) > 0):
		o.Outcome, o.Reason = domain.OutcomeCannotAuthorize, firstOf(f.Reasons, f.Code)
	case f.Class == "tool_failed":
		o.Outcome, o.Code = domain.OutcomeTargetRefused, f.Code
	case f.Class == "uncertain":
		o.Outcome, o.Reason = domain.OutcomeUnknown, f.Code
	default: // authentication_failed, enforcement_failed, a gateway-local cannot_authorize
		o.Outcome, o.Code = domain.OutcomeRefused, f.Code
	}
	if o.Reason != "" && !slices.Contains(o.Reasons, o.Reason) {
		o.Reasons = append(o.Reasons, o.Reason)
	}
	return o
}

// firstOf is the decisive reason: a decision's code, else its first reason.
func firstOf(reasons []string, code string) string {
	if code != "" {
		return code
	}
	if len(reasons) > 0 {
		return reasons[0]
	}
	return ""
}

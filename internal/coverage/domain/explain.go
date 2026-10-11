// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "strings"

// ReasonNotAssessed is the reason of a scope without a snapshot yet.
const ReasonNotAssessed = "not_assessed"

// reasonWords say what each reason code means, for people.
var reasonWords = map[string]string{
	ReasonNotAssessed:       "No coverage snapshot was computed for this scope yet.",
	ReasonConnectionRetired: "The connection is retired.",
	ReasonNoTraffic:         "No traffic through PantherClaw was observed: a connection setting alone proves nothing.",
	ReasonMonitorMode:       "A route is in monitor mode: actions are observed, not prevented.",
	ReasonCooperative:       "A cooperative channel (SDK or hook) the agent could skip: capped at PARTIAL unless the target verifies action tokens.",
	ReasonOpaqueMCP:         "An MCP server whose own egress is not mediated: capped at PARTIAL.",
	ReasonNotActive:         "The connection is quarantined.",
	ReasonNoClosure:         "No sandbox closure evidence: equivalent routes are not proven closed.",
	ReasonClosureFailed:     "The newest sandbox closure failed.",
	ReasonClosureExpired:    "The closure evidence expired.",
	ReasonClosureRebound:    "The connection's revision, gateway or package changed since the closure.",
	ReasonExcluded:          "A person excluded this scope from the claim.",
}

// Explain says what a reason code means. Codes with a kind, such as
// "invalidated:credential" or "route_not_closed:git_ssh", name it.
func Explain(reason string) string {
	if w, ok := reasonWords[reason]; ok {
		return w
	}
	if kind, ok := strings.CutPrefix(reason, ReasonInvalidated+":"); ok {
		return "A change since the evidence invalidated it (" + strings.ReplaceAll(kind, "_", " ") + ")."
	}
	if kind, ok := strings.CutPrefix(reason, ReasonRouteOpen+":"); ok {
		return "The " + strings.ReplaceAll(kind, "_", " ") + " route is not proven closed."
	}
	return reason
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "strings"

// ReasonNotAssessed is the reason of a scope without a snapshot yet.
const ReasonNotAssessed = "not_assessed"

// reasonWords say what each reason code means, for people.
var reasonWords = map[string]string{
	ReasonNotAssessed:    "No coverage snapshot was computed for this scope yet.",
	ReasonNoRoutes:       "No route of this scope is known yet: a connection setting alone proves nothing.",
	ReasonNoChannel:      "No route goes through a PantherClaw gateway channel.",
	ReasonMonitorMode:    "A route is in monitor mode: actions are observed, not prevented.",
	ReasonCooperative:    "A cooperative channel (SDK or hook) the agent could skip: capped at PARTIAL unless a current target-verifier test shows the target refusing calls without an action token.",
	ReasonOpaqueMCP:      "An MCP server whose own egress is not mediated: capped at PARTIAL.",
	ReasonNotActive:      "The connection is quarantined or retired.",
	ReasonAgentHeld:      "The agent holds its own access to the target and can use it directly.",
	ReasonUnverified:     "The target is meant to verify action tokens, but no current target-verifier test shows it does.",
	ReasonInstance:       "An instance of the agent runs outside the sandbox the closure covers.",
	ReasonNoClosure:      "No sandbox closure evidence: equivalent routes are not proven closed.",
	ReasonClosureFailed:  "The newest sandbox closure failed.",
	ReasonClosureExpired: "The closure evidence expired.",
	ReasonClosureRebound: "The connection's revision, gateway, package or credential changed since the closure.",
	ReasonExcluded:       "A person excluded part of this scope: an exclusion never raises the state, and the exclusions are listed.",
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
	if why, ok := strings.CutPrefix(reason, "lapsed:"); ok {
		return "The recorded snapshot lapsed (" + strings.ReplaceAll(why, "_", " ") + "): the scope was recomputed and reads at most PARTIAL."
	}
	return reason
}

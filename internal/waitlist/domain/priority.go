// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the Agent Waitlist's rules (G0 M5 part 2, PN-004):
// entry kinds and how urgent each entry is. An entry's kind, subject,
// priority and deadline come from PantherClaw's records, never from agent
// input (HR-177).
package domain

import "time"

// Entry kinds (design decision 12).
const (
	KindAdmission      = "ADMISSION"
	KindAccessRequest  = "ACCESS_REQUEST"
	KindActionHold     = "ACTION_HOLD"
	KindToolReview     = "TOOL_REVIEW"
	KindRestoration    = "RESTORATION"
	KindReconciliation = "RECONCILIATION"
	// KindAutomationGate: an automation waits at a gate step for people
	// holding automation.approve (G0 M11 part 2 D25, D25a).
	KindAutomationGate = "AUTOMATION_GATE"
)

// Priorities run from 1 (most urgent) to 4.
const (
	PriorityUrgent = 1
	PriorityHigh   = 2
	PriorityNormal = 3
	PriorityLow    = 4
)

// soon is how close a deadline makes an entry one step more urgent.
const soon = 15 * time.Minute

// Priority returns an entry's priority from its kind, the reversibility of
// the definition it concerns (for holds) and its deadline (HR-177): an
// irreversible hold or an unknown outcome is urgent, a restoration high, a
// tool review low; a deadline within 15 minutes raises it one step.
func Priority(kind, reversibility string, deadline, now time.Time) int {
	p := PriorityNormal
	switch kind {
	case KindActionHold:
		switch reversibility {
		case "irreversible":
			p = PriorityUrgent
		case "compensatable":
			p = PriorityHigh
		}
	case KindReconciliation:
		p = PriorityUrgent
	case KindRestoration:
		p = PriorityHigh
	case KindToolReview:
		p = PriorityLow
	}
	if p > PriorityUrgent && !deadline.IsZero() && deadline.Sub(now) <= soon {
		p--
	}
	return p
}

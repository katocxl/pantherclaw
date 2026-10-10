// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"github.com/katocxl/pantherclaw/internal/platform/statemachine"
)

// State is an agent's lifecycle state (F020, ARCHITECTURE §6.2).
type State string

// Lifecycle states.
const (
	StateDiscovered         State = "DISCOVERED"
	StateClaimed            State = "CLAIMED"
	StateVerified           State = "VERIFIED"
	StateObserved           State = "OBSERVED"
	StatePartiallyProtected State = "PARTIALLY_PROTECTED"
	StateProtected          State = "PROTECTED"
	StateSuspended          State = "SUSPENDED"
	StateRetired            State = "RETIRED"
)

// Lifecycle is the agent lifecycle. Every transition is persisted as a
// conditional update (HR-004).
//
//   - A discovered agent is claimed (it gains an owner) or retired
//     (dismissed).
//   - CLAIMED → VERIFIED when its first instance is admitted; VERIFIED →
//     OBSERVED on its first verified request.
//   - The protection states are derived from coverage evidence (M9) and move
//     both ways as that evidence appears and expires (F021).
//   - Any state except RETIRED can be suspended. Leaving SUSPENDED for the
//     state it was suspended from needs an approved RESTORATION request
//     (F563, M5 decision 11; agents/app.Restore), so this table's only
//     other way out is retirement.
//   - RETIRED is terminal (F023).
var Lifecycle = statemachine.New("agent", map[State][]State{
	StateDiscovered:         {StateClaimed, StateSuspended, StateRetired},
	StateClaimed:            {StateVerified, StateSuspended, StateRetired},
	StateVerified:           {StateObserved, StateSuspended, StateRetired},
	StateObserved:           {StatePartiallyProtected, StateProtected, StateSuspended, StateRetired},
	StatePartiallyProtected: {StateObserved, StateProtected, StateSuspended, StateRetired},
	StateProtected:          {StateObserved, StatePartiallyProtected, StateSuspended, StateRetired},
	StateSuspended:          {StateRetired},
})

// Claimed reports whether an agent in state s has an accountable owner.
// A suspended agent's answer depends on the state it was suspended from.
func (s State) Claimed(suspendedFrom State) bool {
	switch s {
	case StateDiscovered, StateRetired:
		return false
	case StateSuspended:
		return suspendedFrom != StateDiscovered && suspendedFrom != ""
	case StateClaimed, StateVerified, StateObserved, StatePartiallyProtected, StateProtected:
		return true
	}
	return false
}

// Usable reports whether instances of an agent in state s may receive
// workload tokens and have requests authorized. Discovered agents have no
// owner and hold no authority (HR-148); suspended and retired agents are
// contained.
func (s State) Usable() bool {
	switch s {
	case StateClaimed, StateVerified, StateObserved, StatePartiallyProtected, StateProtected:
		return true
	case StateDiscovered, StateSuspended, StateRetired:
		return false
	}
	return false
}

// NextAction is what an agent in state s needs next (F020), in words for
// the agent summary.
func (s State) NextAction() string {
	switch s {
	case StateDiscovered:
		return "claim the agent or dismiss the discovery"
	case StateClaimed:
		return "enroll an instance and confirm its fingerprint"
	case StateVerified:
		return "route the agent's requests through a gateway"
	case StateObserved:
		return "issue a task grant and collect coverage evidence"
	case StatePartiallyProtected:
		return "close the routes that are not yet enforced"
	case StateProtected:
		return "keep coverage evidence current"
	case StateSuspended:
		return "restore after review (M5) or retire the agent"
	case StateRetired:
		return "none: the agent is retired"
	}
	return ""
}

// ActivityStatus distinguishes empty states explicitly (F624).
type ActivityStatus string

// Activity statuses.
const (
	ActivityNoInstances       ActivityStatus = "NO_INSTANCES"
	ActivityVerifiedNoActions ActivityStatus = "VERIFIED_NO_ACTIONS"
	ActivityActive            ActivityStatus = "ACTIVE"
)

// Activity derives an agent's activity status from whether any instance has
// ever been admitted and whether any verified request has been observed.
func Activity(everAdmitted, everObserved bool) ActivityStatus {
	switch {
	case everObserved:
		return ActivityActive
	case everAdmitted:
		return ActivityVerifiedNoActions
	default:
		return ActivityNoInstances
	}
}

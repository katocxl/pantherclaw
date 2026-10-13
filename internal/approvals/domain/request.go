// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/statemachine"
)

// State is an approval request's state (HR-171).
type State string

// Request states. PENDING and EVIDENCE_REQUESTED wait for deciders; APPROVED
// waits for the resubmission that consumes it; the others are final.
const (
	StatePending           State = "PENDING"
	StateEvidenceRequested State = "EVIDENCE_REQUESTED"
	StateApproved          State = "APPROVED"
	StateConsumed          State = "CONSUMED"
	StateDeclined          State = "DECLINED"
	StateExpired           State = "EXPIRED"
	StateInvalidated       State = "INVALIDATED"
	StateSuperseded        State = "SUPERSEDED"
)

// Lifecycle is the request state machine. An approved request returns to
// PENDING when a void leaves a requirement short (HR-170); a changed binding
// supersedes a request, never updates it. A consumed request returns to
// APPROVED only when the server can prove its permit sent nothing: the
// permit was released without reaching DISPATCHING (HR-011, M6 slice 23).
var Lifecycle = statemachine.New("approval request", map[State][]State{
	StatePending:           {StateEvidenceRequested, StateApproved, StateDeclined, StateExpired, StateInvalidated, StateSuperseded},
	StateEvidenceRequested: {StatePending, StateDeclined, StateExpired, StateInvalidated, StateSuperseded},
	StateApproved:          {StateConsumed, StatePending, StateExpired, StateInvalidated, StateSuperseded},
	StateConsumed:          {StateApproved},
})

// Live reports whether the request still waits for deciders or for its
// resubmission, and so holds a hold slot.
func (s State) Live() bool {
	return s == StatePending || s == StateEvidenceRequested || s == StateApproved
}

// Reason codes of decisions about held actions (G0 M5 part 2).
const (
	ReasonApprovalPending         = "APPROVAL_PENDING"
	ReasonApprovalDeclined        = "APPROVAL_DECLINED"
	ReasonApprovalExpired         = "APPROVAL_EXPIRED"
	ReasonApprovalSatisfied       = "APPROVAL_SATISFIED"
	ReasonNarrowerProposed        = "NARROWER_PROPOSED"
	ReasonHoldLimitReached        = "HOLD_LIMIT_REACHED"
	ReasonStepUpSubjectNotAPerson = "STEP_UP_SUBJECT_NOT_A_PERSON"
	ReasonRequirementInvalid      = "REQUIREMENT_INVALID"
)

// End reasons of final requests. A declined request ends with
// APPROVAL_DECLINED or NARROWER_PROPOSED, an expired one with
// APPROVAL_EXPIRED, a superseded one with BINDING_CHANGED, and an
// invalidated one with the change that made it moot.
const (
	EndDeclined          = ReasonApprovalDeclined
	EndNarrowerProposed  = ReasonNarrowerProposed
	EndExpired           = ReasonApprovalExpired
	EndBindingChanged    = "BINDING_CHANGED"
	EndGrantRevoked      = "GRANT_REVOKED"
	EndGrantRevised      = "GRANT_REVISED"
	EndGuardrailChanged  = "GUARDRAIL_CHANGED"
	EndDefinitionChanged = "DEFINITION_CHANGED"
	EndAgentSuspended    = "AGENT_SUSPENDED"
	EndAgentRetired      = "AGENT_RETIRED"
	EndKillSwitch        = "KILL_SWITCH_ENGAGED"
	EndContained         = "CONTAINMENT_CHANGED"
	EndRunEnded          = "RUN_ENDED"
	EndAgentChanged      = "AGENT_CHANGED"
)

// Times are a request's deadlines as stored.
type Times struct {
	Deadline         time.Time
	EvidenceDeadline *time.Time
	ConsumeBy        *time.Time
}

// At returns the state a request has at now, by the database clock
// (HR-039): a live request past its deadline, its evidence deadline or its
// consume-by time has expired, whatever its stored state says, even when
// the janitor has not run. A final state is returned unchanged.
func At(s State, t Times, now time.Time) (State, string) {
	if !s.Live() {
		return s, ""
	}
	switch {
	case !now.Before(t.Deadline):
		return StateExpired, EndExpired
	case s == StateEvidenceRequested && t.EvidenceDeadline != nil && !now.Before(*t.EvidenceDeadline):
		return StateExpired, EndExpired
	case s == StateApproved && t.ConsumeBy != nil && !now.Before(*t.ConsumeBy):
		return StateExpired, EndExpired
	}
	return s, ""
}

// Wait states as a waiter sees them (HR-174).
const (
	WaitPending           = "PENDING"
	WaitEvidenceRequested = "EVIDENCE_REQUESTED"
	WaitReady             = "READY"
	WaitDeclined          = "DECLINED"
	WaitNarrowerProposed  = "NARROWER_PROPOSED"
	WaitExpired           = "EXPIRED"
	WaitSuperseded        = "SUPERSEDED"
	WaitInvalidated       = "INVALIDATED"
	WaitConsumed          = "CONSUMED"
)

// WaitState maps a request's state (as At returns it) to what a waiter
// sees: states and codes only.
func WaitState(s State, endReason string) string {
	switch s {
	case StatePending:
		return WaitPending
	case StateEvidenceRequested:
		return WaitEvidenceRequested
	case StateApproved:
		return WaitReady
	case StateConsumed:
		return WaitConsumed
	case StateDeclined:
		if endReason == EndNarrowerProposed {
			return WaitNarrowerProposed
		}
		return WaitDeclined
	case StateExpired:
		return WaitExpired
	case StateSuperseded:
		return WaitSuperseded
	case StateInvalidated:
		return WaitInvalidated
	}
	return WaitExpired
}

// Terminal reports whether a final request ends its transaction as DENY
// (HR-171): a decline, a narrower proposal and an expiry do; a superseded
// or invalidated request does not, and the next evaluation decides again.
func Terminal(s State) bool {
	return s == StateDeclined || s == StateExpired
}

// maxInvalidationKey bounds an invalidation key (00082).
const maxInvalidationKey = 300

// InvalidationKey is the key of the approval requests that a new value of
// a fact about a subject supersedes (G0 M8, HR-205), for example
// github.pull.head@github.pull_request:acme/payments#7. A key longer than
// the column holds is written as "sha256:" and the SHA-256 of the key in
// hex, so the requests about a long subject id are superseded too. Such a
// key never equals a written-out one, which always has an "@".
func InvalidationKey(fact, subjectType, subjectID string) string {
	k := fact + "@" + subjectType + ":" + subjectID
	if len(k) > maxInvalidationKey {
		sum := sha256.Sum256([]byte(k))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	return k
}

// MemberKey is the invalidation key of the approval requests bound to one
// member of an object fact (HR-030 option B, founder decision 2026-10-13):
// a new value of that member supersedes them, a change to any other member
// does not. For example github.pull.head[sha]@github.pull_request:acme/payments#7.
func MemberKey(fact, member, subjectType, subjectID string) string {
	return InvalidationKey(fact+"["+member+"]", subjectType, subjectID)
}

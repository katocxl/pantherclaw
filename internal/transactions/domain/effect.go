// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the rules of what happened after a decision (G0 M7
// track A): execution states derived from the records (F471–F479), effect
// states assessed from verifier observations (F480–F499, HR-191), and the
// reconciliation of unknown outcomes (F501–F503, HR-192, HR-193). It is
// pure: no I/O, no clock of its own.
package domain

import (
	"maps"
	"slices"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// EffectState is what is known about an action's effect (ARCHITECTURE
// §6.2, PAP-1 §9.3).
type EffectState string

// Effect states.
const (
	Confirmed          EffectState = "CONFIRMED"
	NoneConfirmed      EffectState = "NONE_CONFIRMED"
	Partial            EffectState = "PARTIAL"
	PropagationPending EffectState = "PROPAGATION_PENDING"
	Conflicting        EffectState = "CONFLICTING"
	Unverifiable       EffectState = "UNVERIFIABLE"
	Unknown            EffectState = "UNKNOWN"
	Compensated        EffectState = "COMPENSATED"
)

// EffectStates are every effect state.
var EffectStates = []EffectState{
	Confirmed, NoneConfirmed, Partial, PropagationPending, Conflicting, Unverifiable, Unknown, Compensated,
}

// Valid reports whether s is an effect state.
func (s EffectState) Valid() bool { return slices.Contains(EffectStates, s) }

// Purpose is why a verification read is made.
type Purpose string

// Verification purposes.
const (
	// PurposeFollowUp reads the object the target said it created, after
	// an accepted outcome, by its reference.
	PurposeFollowUp Purpose = "follow_up"
	// PurposeReconcile looks for the effect of an unknown outcome in a
	// listing, by the dispatch's idempotency key.
	PurposeReconcile Purpose = "reconcile"
	// PurposeTargetLog lists what the target created in a window (HR-112).
	PurposeTargetLog Purpose = "target_log"
	// PurposeOrgScan scans the GitHub organization behind a GitHub App
	// connection (G0 M8, HR-209).
	PurposeOrgScan Purpose = "org_scan"
	// PurposeConnectionTest makes a connection's harmless test read (G0 M8
	// track C, F354). It belongs to no transaction.
	PurposeConnectionTest Purpose = "connection_test"
	// PurposeConsequence reads the effect of a consequence the server
	// opened when the action that starts it was confirmed (a deployment a
	// merge starts; G0 M8 W1c): never dispatched, it is found by a
	// matched lookup.
	PurposeConsequence Purpose = "consequence"
	// PurposeRotationTest tests a GitHub App key rotation's candidate at
	// GitHub, and PurposeRotationConfirm confirms GitHub refuses the old
	// key (G0 M20 S20c, D253). Neither belongs to a transaction; the lease
	// carries the sealed credential.
	PurposeRotationTest    Purpose = "credential_rotation_test"
	PurposeRotationConfirm Purpose = "credential_rotation_confirm"
)

// DownstreamState is what is known about the consequences of a confirmed
// action, apart from its own effect (G0 M17 D102, F414, HR-451). It is
// empty when its decision predicted none.
type DownstreamState string

// Downstream states.
const (
	// DownstreamPending: a consequence opened for verification is not
	// confirmed yet.
	DownstreamPending DownstreamState = "PENDING"
	// DownstreamConfirmed: every consequence opened for it is confirmed,
	// by its own evidence.
	DownstreamConfirmed DownstreamState = "CONFIRMED"
	// DownstreamUnconfirmed: a consequence's verifier or deadline asked a
	// person, or its effect state says it did not take effect.
	DownstreamUnconfirmed DownstreamState = "UNCONFIRMED"
	// DownstreamNotVerifiable: a predicted consequence could not be opened
	// for verification (HR-450). It never becomes CONFIRMED.
	DownstreamNotVerifiable DownstreamState = "NOT_VERIFIABLE"
)

// Consequence is one consequence transaction as a roll-up sees it.
type Consequence struct {
	Effect EffectState
	// Downstream is its own downstream state, for a consequence that has
	// consequences of its own.
	Downstream DownstreamState
	// Questioned: a person was asked whether it took effect (an open
	// consequence_unconfirmed reconciliation, or one released as not
	// occurred).
	Questioned bool
}

// Downstream is the downstream state of an action from the consequences
// opened for it, and whether one of its predicted consequences could not
// be opened (capped). Precedence over the whole subtree is UNCONFIRMED >
// NOT_VERIFIABLE > PENDING > CONFIRMED (D102, D131):
//   - UNCONFIRMED when any consequence is questioned, has an effect state
//     other than confirmed or still pending, or is unconfirmed downstream;
//   - otherwise NOT_VERIFIABLE when capped or any consequence is not
//     verifiable downstream: it never becomes CONFIRMED (HR-450);
//   - CONFIRMED only when every one is confirmed, with its own subtree
//     confirmed, by its own evidence (HR-451);
//   - PENDING otherwise.
func Downstream(cs []Consequence, capped bool) DownstreamState {
	unverifiable, confirmed := capped, len(cs) > 0
	for _, c := range cs {
		switch {
		case c.Questioned, c.Downstream == DownstreamUnconfirmed:
			return DownstreamUnconfirmed
		case c.Effect == Confirmed:
			unverifiable = unverifiable || c.Downstream == DownstreamNotVerifiable
			confirmed = confirmed && (c.Downstream == "" || c.Downstream == DownstreamConfirmed)
		case c.Effect == "" || c.Effect == PropagationPending:
			unverifiable = unverifiable || c.Downstream == DownstreamNotVerifiable
			confirmed = false
		default:
			return DownstreamUnconfirmed
		}
	}
	switch {
	case unverifiable:
		return DownstreamNotVerifiable
	case confirmed:
		return DownstreamConfirmed
	default:
		return DownstreamPending
	}
}
// Rotation reports whether p is a rotation lease's purpose.
func (p Purpose) Rotation() bool { return p == PurposeRotationTest || p == PurposeRotationConfirm }

// Observation is what one verification read reported (HR-190): only the
// fields the verifier declares, by JSON pointer, as their JSON text (a
// string without quotes, a number or a boolean as written), never a body.
type Observation struct {
	// HTTPStatus is the target's status; 0 when the read failed before an
	// answer.
	HTTPStatus int
	// Found says whether the object was found: by reference, a 2xx answer;
	// in a listing, an item whose correlation value matched.
	Found bool
	// Complete says whether a listing was read to its end.
	Complete bool
	Fields   map[string]string
	At       time.Time
}

// Expected is what the action says each expected field must be: the JSON
// pointer of the observed field and the canonical value of the action field
// it is compared with (defs.Expectation.Equals).
type Expected map[string]string

// Assessment is the meaning of one observation.
type Assessment struct {
	// State is the effect state the observation shows; empty when the read
	// was inconclusive (it failed, or a listing was cut short).
	State EffectState
	// Level is the verification level a CONFIRMED or NONE_CONFIRMED state
	// reaches.
	Level defs.Level
	// Final says verification can stop: the state will not improve by
	// reading again.
	Final bool
	// ObjectFound says the object exists, whatever its status.
	ObjectFound bool
	// Mismatched lists the expected fields that differed (CONFLICTING).
	Mismatched []string
	// Reason is a stable code for the receipt and the explorer.
	Reason string
	// NeedsPerson says the observation suggests the effect did not happen
	// without showing it (a failed deployment, or none by the deadline): a
	// person decides (HR-192), so it never resolves towards occurred.
	NeedsPerson bool
}

// Assessment reason codes.
const (
	ReasonReadFailed       = "READ_FAILED"
	ReasonListingCut       = "LISTING_INCOMPLETE"
	ReasonNotFoundYet      = "NOT_FOUND_WITHIN_WINDOW"
	ReasonNotFoundAccepted = "NOT_FOUND_AFTER_ACCEPTANCE"
	ReasonNotInListing     = "NOT_IN_COMPLETE_LISTING"
	ReasonMismatch         = "OBSERVED_DIFFERS"
	ReasonStatusConfirmed  = "STATUS_CONFIRMED"
	ReasonStatusPending    = "STATUS_PENDING"
	ReasonStatusNone       = "STATUS_NONE"
	ReasonStatusOther      = "STATUS_UNRECOGNIZED"
	ReasonFound            = "FOUND"
	ReasonStatusReconcile  = "STATUS_NEEDS_A_PERSON"
	ReasonNotFoundDeadline = "NOT_FOUND_BY_DEADLINE"
)

// Reasons an effect is UNVERIFIABLE (F485, G0 M7 design decision 2).
const (
	// ReasonNoVerifier: the definition declares no verifier, or one
	// without the M7 fields, which cannot be run.
	ReasonNoVerifier = "NO_VERIFIER"
	// ReasonVerifierCannotRead: the definition's verifier has no read it
	// can make for this outcome (no connection to read through, no
	// reference the target named and no lookup).
	ReasonVerifierCannotRead = "VERIFIER_CANNOT_READ"
)

// CoveragePartial is the label the effect receipts of a cooperative
// channel's transaction carry (HR-024, HR-186): the agent performed the
// action with its own access, so whatever a verifier later observes, the
// route itself was only partly mediated (G0 M7 design decision 2).
const CoveragePartial = "PARTIAL"

// Cooperative reports whether a transaction's channel is a cooperative one
// (the hook, the SDK, an AuthZEN enforcement point: G0 M14 D4), whose agent
// or enforcement point performs the allowed action itself.
func Cooperative(channel string) bool {
	return channel == "hook" || channel == "sdk" || channel == "authzen"
}

// UnverifiableReason says why the effect of an accepted or delegated
// outcome of definition d is UNVERIFIABLE, or "" when it is not: a
// verification read was scheduled for it, or d only reads, so it has no
// effect to verify (G0 M7 design decision 2: a definition without a
// verifier gives UNVERIFIABLE with the reason).
func UnverifiableReason(d *defs.Definition, scheduled bool) string {
	switch {
	case scheduled || d.Access != defs.AccessWrite:
		return ""
	case d.Verifier == nil || !d.Verifier.Extended():
		return ReasonNoVerifier
	}
	return ReasonVerifierCannotRead
}

// Assess applies G0 M7 design decision 2 to one observation of verifier v,
// made for purpose p of an action dispatched at dispatched whose expected
// field values are want. Nothing the agent or the write's own answer said
// is an observation (HR-191).
func Assess(v *defs.VerifierSpec, p Purpose, want Expected, o Observation, dispatched time.Time) Assessment {
	window := dispatched.Add(time.Duration(v.WithinSeconds) * time.Second)
	switch {
	case o.HTTPStatus == 0 || o.HTTPStatus >= 500 || (o.HTTPStatus >= 400 && o.HTTPStatus != 404):
		return Assessment{Reason: ReasonReadFailed}
	case !o.Found && p == PurposeConsequence:
		// Nothing was dispatched, so its absence is no conflict: pending
		// within the window, then a person's question.
		if !o.Complete {
			return Assessment{Reason: ReasonListingCut}
		}
		if o.At.Before(window) {
			return Assessment{State: PropagationPending, Reason: ReasonNotFoundYet}
		}
		return Assessment{Final: true, NeedsPerson: true, Reason: ReasonNotFoundDeadline}
	case !o.Found && p == PurposeFollowUp:
		// The target accepted the write, yet the object is not there.
		if o.At.Before(window) {
			return Assessment{State: PropagationPending, Reason: ReasonNotFoundYet}
		}
		return Assessment{State: Conflicting, Final: true, Reason: ReasonNotFoundAccepted}
	case !o.Found && !o.Complete:
		return Assessment{Reason: ReasonListingCut}
	case !o.Found && o.At.Before(window):
		// A complete listing without it, but the target may still be
		// working on the request: not yet evidence of absence.
		return Assessment{Reason: ReasonNotFoundYet}
	case !o.Found:
		return Assessment{State: NoneConfirmed, Level: defs.LevelFollowUp, Final: true, Reason: ReasonNotInListing}
	}
	var mismatched []string
	for _, ptr := range slices.Sorted(maps.Keys(want)) {
		if got, ok := o.Fields[ptr]; !ok || got != want[ptr] {
			mismatched = append(mismatched, ptr)
		}
	}
	if len(mismatched) > 0 {
		return Assessment{State: Conflicting, Final: true, ObjectFound: true, Mismatched: mismatched, Reason: ReasonMismatch}
	}
	s := v.States
	if s == nil {
		return Assessment{State: Confirmed, Level: v.Reaches(), Final: true, ObjectFound: true, Reason: ReasonFound}
	}
	status, ok := o.Fields[s.Field]
	switch {
	case ok && slices.Contains(s.Confirmed, status):
		return Assessment{State: Confirmed, Level: v.Reaches(), Final: true, ObjectFound: true, Reason: ReasonStatusConfirmed}
	case ok && slices.Contains(s.Pending, status):
		return Assessment{State: PropagationPending, ObjectFound: true, Reason: ReasonStatusPending}
	case ok && slices.Contains(s.None, status):
		return Assessment{State: NoneConfirmed, Level: v.Reaches(), Final: true, ObjectFound: true, Reason: ReasonStatusNone}
	case ok && slices.Contains(s.Reconcile, status):
		return Assessment{Final: true, ObjectFound: true, NeedsPerson: true, Reason: ReasonStatusReconcile}
	}
	// The object exists but its status means nothing the package reviewed:
	// it happened, at most at follow-up level, and is read again.
	return Assessment{ObjectFound: true, Reason: ReasonStatusOther}
}

// AtDeadline is the effect state when a verifier's window closes: the last
// conclusive state seen, or UNKNOWN when none was conclusive. A state still
// pending at the deadline is inconclusive (F499) and named by the caller.
func AtDeadline(last Assessment) EffectState {
	if last.Final && last.State != "" {
		return last.State
	}
	return Unknown
}

// Occurred reports whether an assessment shows that the effect happened,
// which is the only direction evidence may resolve a reconciliation in
// (HR-192): a confirmed effect, or the object found while still pending or
// with an unreviewed status.
func (a Assessment) Occurred() bool {
	return a.State == Confirmed || (a.ObjectFound && !a.NeedsPerson && a.State != Conflicting && a.State != NoneConfirmed)
}

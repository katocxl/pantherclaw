// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"regexp"
	"unicode/utf8"
)

// ChangeKind names one entry of an agent's append-only history (F024).
type ChangeKind string

// Change kinds written by M3. Later milestones add their own (grants,
// coverage); the schema accepts any dotted lowercase name.
const (
	ChangeCreated              ChangeKind = "agent.created"
	ChangeDiscovered           ChangeKind = "agent.discovered"
	ChangeClaimed              ChangeKind = "agent.claimed"
	ChangeMerged               ChangeKind = "agent.merged"
	ChangeUpdated              ChangeKind = "agent.updated"
	ChangeOwnershipTransferred ChangeKind = "agent.ownership_transferred"
	ChangeVerified             ChangeKind = "agent.verified"
	ChangeObserved             ChangeKind = "agent.observed"
	ChangeSuspended            ChangeKind = "agent.suspended"
	ChangeRetired              ChangeKind = "agent.retired"
	ChangeRestored             ChangeKind = "agent.restored"
	ChangeInstanceEnrolled     ChangeKind = "instance.enrolled"
	ChangeInstanceAdmitted     ChangeKind = "instance.admitted"
	ChangeInstanceAutoAdmitted ChangeKind = "instance.auto_admitted"
	ChangeInstanceRejected     ChangeKind = "instance.rejected"
	ChangeInstanceRevoked      ChangeKind = "instance.revoked"
	ChangeInstanceExpired      ChangeKind = "instance.expired"
	ChangeInstanceDrift        ChangeKind = "instance.drift"
	ChangeInstanceNetwork      ChangeKind = "instance.network_changed"
)

// kindPattern matches the agent_changes.kind CHECK.
var kindPattern = regexp.MustCompile(`^[a-z][a-z_]{1,39}(\.[a-z][a-z_]{1,39}){0,2}$`)

// Actor names who made a change: "user:<id>", "sa:<id>", "instance:<id>" or
// "system".
type Actor string

// System is the actor for changes PantherClaw makes itself.
const System Actor = "system"

// UserActor names a user.
func UserActor(id fmt.Stringer) Actor { return Actor("user:" + id.String()) }

// ServiceAccountActor names a service account.
func ServiceAccountActor(id fmt.Stringer) Actor { return Actor("sa:" + id.String()) }

// InstanceActor names an agent instance.
func InstanceActor(id fmt.Stringer) Actor { return Actor("instance:" + id.String()) }

// Change is one history entry. Details carry ids and short facts only,
// never secrets or untrusted text (HR-056).
type Change struct {
	Kind    ChangeKind
	Actor   Actor
	Reason  string
	Details map[string]string
}

// Validate checks a change before it is written.
func (c Change) Validate() error {
	if !kindPattern.MatchString(string(c.Kind)) {
		return fmt.Errorf("%w: change kind %q", ErrInvalid, c.Kind)
	}
	if c.Actor == "" || utf8.RuneCountInString(string(c.Actor)) > 200 {
		return fmt.Errorf("%w: change actor", ErrInvalid)
	}
	if utf8.RuneCountInString(c.Reason) > MaxReasonLen || !printable(c.Reason) {
		return fmt.Errorf("%w: change reason", ErrInvalid)
	}
	if len(c.Details) > 32 {
		return fmt.Errorf("%w: too many change details", ErrInvalid)
	}
	for k, v := range c.Details {
		if !kindPattern.MatchString(k) || utf8.RuneCountInString(v) > 256 || !printable(v) {
			return fmt.Errorf("%w: change detail %q", ErrInvalid, k)
		}
	}
	return nil
}

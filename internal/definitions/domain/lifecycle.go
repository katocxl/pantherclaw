// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/platform/statemachine"
)

// State is the lifecycle state of a package version in an org (F394).
type State string

// Lifecycle states.
const (
	StateUnclassified State = "UNCLASSIFIED"
	StateDraft        State = "DRAFT"
	StateReviewed     State = "REVIEWED"
	StateActive       State = "ACTIVE"
	StateStale        State = "STALE"
	StateQuarantined  State = "QUARANTINED"
	StateRetired      State = "RETIRED"
)

// Lifecycle is the definition lifecycle. Review and activation are separate
// steps (F395); stale and quarantined meanings return only through a fresh
// review (F402); retired versions are kept for evidence but never used again
// (F398). Nothing becomes ACTIVE without passing REVIEWED, so a
// model-proposed mapping stays a draft until it is reviewed (F404). REVIEWED
// to QUARANTINED is the revoke of a catalogue server only (G0 M24 D267): the
// Importer refuses it, so no person moves a version there by hand.
var Lifecycle = statemachine.New("definition", map[State][]State{
	StateUnclassified: {StateDraft, StateRetired},
	StateDraft:        {StateReviewed, StateRetired},
	StateReviewed:     {StateActive, StateQuarantined, StateRetired},
	StateActive:       {StateStale, StateQuarantined, StateRetired},
	StateStale:        {StateReviewed, StateQuarantined, StateRetired},
	StateQuarantined:  {StateReviewed, StateRetired},
})

// Usable reports whether actions may be authorized under a definition in
// state s. Only ACTIVE meaning maps actions (F372); anything else is
// CANNOT_AUTHORIZE (definition_inactive, PAP-1 §12).
func (s State) Usable() bool { return s == StateActive }

// Pin is the package version an org currently uses.
type Pin struct {
	Package string
	Version string
	// Digest is "sha256:<hex>" of the exact package bytes listed in the
	// signed targets metadata.
	Digest string
}

var (
	// ErrPinRollback reports an attempt to move a pin to an older version.
	ErrPinRollback = errors.New("definitions: package pins only move forward")
	// ErrPinConflict reports a different package under an already pinned
	// version.
	ErrPinConflict = errors.New("definitions: version already pinned with different content")
)

// CheckPinAdvance allows moving an org's pin from current to next only
// forward (HR-123, anti-rollback). Re-importing the same version with the
// same digest is a no-op; the same version with other bytes is a conflict.
// A nil current means the package was never pinned.
func CheckPinAdvance(current *Pin, next Pin) error {
	nv, err := ParseVersion(next.Version)
	if err != nil {
		return err
	}
	if current == nil {
		return nil
	}
	if current.Package != next.Package {
		return fmt.Errorf("%w: pin is for %s, not %s", ErrInvalid, current.Package, next.Package)
	}
	cv, err := ParseVersion(current.Version)
	if err != nil {
		return err
	}
	switch c := nv.Compare(cv); {
	case c < 0:
		return fmt.Errorf("%w: %s %s is older than the pinned %s", ErrPinRollback, next.Package, nv, cv)
	case c == 0 && next.Digest != current.Digest:
		return fmt.Errorf("%w: %s %s", ErrPinConflict, next.Package, nv)
	}
	return nil
}

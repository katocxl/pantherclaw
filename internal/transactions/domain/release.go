// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"errors"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The release of an unknown outcome (G0 M7 slice A11, design decision 3,
// HR-192): "it did not happen" frees the held budget only when an
// independent person confirms it on the reconciliation page with a written
// basis and a WebAuthn assertion over the release binding (Release).

// Errors of the release rules.
var (
	// ErrNotReleasable: only an open unknown outcome is released; a
	// conflicting effect's budget was committed and stays committed.
	ErrNotReleasable = errors.New("transactions: only an open unknown outcome is released")
	// ErrReleaseExpired: the release binding's expiry has passed.
	ErrReleaseExpired = errors.New("transactions: the release expired")
	// ErrReleaseMismatch: the assertion's ceremony did not sign this
	// release (another basis, other evidence or another expiry), or is not
	// this person's open ceremony for the reconciliation in this browser
	// session.
	ErrReleaseMismatch = errors.New("transactions: the security key did not sign this release")
)

// ReleaseTTL is how long a release binding is valid: the 5 minutes of the
// BINDING ceremony its assertion is made in.
const ReleaseTTL = 5 * time.Minute

// MaxEvidence is the most observations a person's resolution names.
const MaxEvidence = 64

// CheckReleasable checks that a task of kind, in state, may be released.
func CheckReleasable(kind TaskKind, state TaskState) error {
	switch {
	case state != TaskOpen:
		return ErrNotOpen
	case kind != KindUnknownOutcome:
		return ErrNotReleasable
	}
	return nil
}

// CheckIndependent checks that user, a person, is none of the people who
// may not release the run's unknown outcome: its launcher and represented
// principal, and the agent's owner and backup owner.
func CheckIndependent(user ids.UUID, p Party) error {
	if user.IsZero() || slices.Contains([]ids.UUID{p.Launcher, p.Principal, p.Owner, p.BackupOwner}, user) {
		return ErrNotIndependent
	}
	return nil
}

// ReleaseExpiry is the expires_at of a release bound at now: ReleaseTTL
// later, in whole seconds, as the release document states it.
func ReleaseExpiry(now time.Time) time.Time {
	return now.Add(ReleaseTTL).UTC().Truncate(time.Second)
}

// CheckReleaseLive checks that a release binding that expires at expires
// may still be used at now.
func CheckReleaseLive(expires, now time.Time) error {
	if expires.IsZero() || !now.Before(expires) {
		return ErrReleaseExpired
	}
	return nil
}

// ShownEvidence returns the observations a person was shown, sorted and
// without repeats, as the release document lists them.
func ShownEvidence(evidence []ids.UUID) []ids.UUID {
	out := slices.Clone(evidence)
	slices.SortFunc(out, func(a, b ids.UUID) int { return bytes.Compare(a[:], b[:]) })
	return slices.Compact(out)
}

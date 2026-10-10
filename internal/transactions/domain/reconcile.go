// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TaskState is a reconciliation task's state (HR-192).
type TaskState string

// Reconciliation task states.
const (
	TaskOpen        TaskState = "OPEN"
	TaskOccurred    TaskState = "OCCURRED"
	TaskNotOccurred TaskState = "NOT_OCCURRED"
)

// TaskKind is why a reconciliation task exists.
type TaskKind string

// Reconciliation task kinds.
const (
	// KindUnknownOutcome: the dispatch's outcome is unknown; its
	// reservations and dedupe claim are held until the task is resolved.
	KindUnknownOutcome TaskKind = "unknown_outcome"
	// KindConflictingEffect: the target accepted, yet a verifier read
	// disagrees. The committed budget stays committed; the person records
	// which observation is authoritative.
	KindConflictingEffect TaskKind = "conflicting_effect"
)

// Via is what resolved a task.
type Via string

// Resolution sources.
const (
	ViaVerifier   Via = "verifier"
	ViaLateReport Via = "late_report"
	ViaTargetLog  Via = "target_log"
	ViaPerson     Via = "person"
)

// Errors of reconciliation rules.
var (
	ErrNotOpen           = errors.New("transactions: the reconciliation is no longer open")
	ErrEvidenceReleases  = errors.New("transactions: evidence resolves a reconciliation only towards occurred")
	ErrNotAPerson        = errors.New("transactions: only a person releases a reconciliation")
	ErrNotIndependent    = errors.New("transactions: the run's launcher, its represented principal and the agent's owners cannot resolve its reconciliation")
	ErrBasisRequired     = errors.New("transactions: a person resolves a reconciliation with a written basis")
	ErrBasisTooLong      = errors.New("transactions: the basis is at most 2000 characters")
	ErrTooMuchEvidence   = errors.New("transactions: at most 64 observations can be named as evidence")
	ErrNotEvidence       = errors.New("transactions: evidence names only the transaction's observations, the authoritative one among them")
	ErrLinkOrder         = errors.New("transactions: a compensating or recovering transaction is decided after the original was dispatched")
	ErrLinkSelf          = errors.New("transactions: a transaction cannot be linked to itself")
	ErrNotCompensateable = errors.New("transactions: only a confirmed effect can become compensated")
)

// MaxBasis is the longest basis a person may write (characters).
const MaxBasis = 2000

// CheckResolution checks that a task in state from may be resolved to to
// by via (HR-192): only an open task resolves, evidence resolves only
// towards OCCURRED, and only a person reaches NOT_OCCURRED.
func CheckResolution(from, to TaskState, via Via) error {
	switch {
	case from != TaskOpen:
		return ErrNotOpen
	case to != TaskOccurred && to != TaskNotOccurred:
		return ErrNotOpen
	case via != ViaPerson && to != TaskOccurred:
		return ErrEvidenceReleases
	}
	return nil
}

// Party is who may not resolve a run's reconciliation (HR-192): the run's
// launcher and represented principal, and the agent's owner and backup
// owner, as user ids.
type Party struct {
	Launcher, Principal, Owner, BackupOwner ids.UUID
}

// CheckResolver checks that user, a person, is independent of the run and
// the agent, and that their basis is acceptable.
func CheckResolver(human bool, user ids.UUID, p Party, basis string, evidence []ids.UUID) error {
	switch {
	case !human:
		return ErrNotAPerson
	case slices.Contains([]ids.UUID{p.Launcher, p.Principal, p.Owner, p.BackupOwner}, user):
		return ErrNotIndependent
	case basis == "":
		return ErrBasisRequired
	case len([]rune(basis)) > MaxBasis:
		return ErrBasisTooLong
	case len(evidence) > 64:
		return ErrTooMuchEvidence
	}
	return nil
}

// CheckOccurred checks a person's "occurred" (design decision 3). It only
// commits, the safe direction, so the person need not be independent of
// the run; they write a basis and name the observations they relied on,
// among which the authoritative one, when they name one.
func CheckOccurred(human bool, basis string, evidence []ids.UUID, authoritative *ids.UUID) error {
	switch {
	case !human:
		return ErrNotAPerson
	case basis == "":
		return ErrBasisRequired
	case len([]rune(basis)) > MaxBasis:
		return ErrBasisTooLong
	case len(evidence) > 64:
		return ErrTooMuchEvidence
	case authoritative != nil && !slices.Contains(evidence, *authoritative):
		return ErrNotEvidence
	}
	return nil
}

// Release is what a person's WebAuthn assertion binds when they release an
// unknown outcome (G0 M7 design decision 3): the reconciliation, its
// transaction, the resolution, the SHA-256 of the basis they wrote, the
// observations they were shown and the binding's expiry.
type Release struct {
	Reconciliation ids.UUID
	Transaction    ids.UUID
	Basis          string
	Evidence       []ids.UUID
	ExpiresAt      time.Time
}

// Binding returns SHA-256 of Document, the challenge of the release's
// WebAuthn assertion.
func (r Release) Binding() ([32]byte, error) {
	doc, err := r.Document()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(doc), nil
}

// Document returns JCS({v, reconciliation, transaction, resolution,
// basis_sha256, evidence, expires_at}): what a person's key signs when they
// release an unknown outcome. Hashes are base64url without padding,
// evidence is sorted, and expires_at is RFC 3339 UTC in whole seconds (as
// approval bindings, PAP-1 §8).
func (r Release) Document() ([]byte, error) {
	basis := sha256.Sum256([]byte(r.Basis))
	ev := make([]string, len(r.Evidence))
	for i, id := range r.Evidence {
		ev[i] = id.String()
	}
	slices.Sort(ev)
	doc := map[string]any{
		"v": 1, "reconciliation": r.Reconciliation.String(), "transaction": r.Transaction.String(),
		"resolution": "not_occurred", "basis_sha256": base64.RawURLEncoding.EncodeToString(basis[:]),
		"evidence": ev, "expires_at": r.ExpiresAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	b, err := json.Marshal(doc, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	v := jsontext.Value(b)
	if err := v.Canonicalize(); err != nil {
		return nil, err
	}
	return v, nil
}

// LinkKind is how a later transaction relates to an earlier one (HR-193).
type LinkKind string

// Link kinds.
const (
	LinkCompensates LinkKind = "compensates"
	LinkRecovers    LinkKind = "recovers"
)

// CheckLink checks a link from a later transaction, decided at decided, to
// an earlier one dispatched at dispatched (the zero time when it never
// was): the later one must be another transaction, decided after the
// earlier one was sent.
func CheckLink(from, to ids.UUID, decided, dispatched time.Time) error {
	switch {
	case from == to:
		return ErrLinkSelf
	case dispatched.IsZero() || !decided.After(dispatched):
		return ErrLinkOrder
	}
	return nil
}

// CompensatedFrom checks that a transaction whose effect is current may
// become COMPENSATED: only a confirmed effect can be (F487); the original
// records and budget stay as they are.
func CompensatedFrom(current EffectState) error {
	if current != Confirmed {
		return ErrNotCompensateable
	}
	return nil
}

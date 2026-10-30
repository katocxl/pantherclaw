// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"net/http"
	"strconv"
	"time"
)

// Target-confirmed rotation of a GitHub App key (G0 M20 S20c, D253, F424;
// HR-517..520). GitHub has no API that creates or deletes an App private
// key, so a person creates the new key in the App's settings, seals it and
// later deletes the old one there. The gateway tests the candidate at
// GitHub before activation and confirms the old key is refused before the
// old credential is revoked. Migration 00239 holds the database to the same
// moves; everything here is pure.

// RotationState is a rotation's state.
type RotationState string

// Rotation states, in the order a rotation moves through them.
const (
	// RotationRequested: a person with connection.manage asked for a
	// rotation, after the preview of who shares the credential (HR-252).
	RotationRequested RotationState = "REQUESTED"
	// RotationCandidateSealed: the new key is sealed as a CANDIDATE
	// credential, which no gateway configuration serves (HR-517).
	RotationCandidateSealed RotationState = "CANDIDATE_SEALED"
	// RotationTesting: the gateway tests the candidate at GitHub under a
	// credential_rotation_test lease; no token is minted.
	RotationTesting RotationState = "TESTING"
	// RotationActivating: the candidate is ACTIVE and the old key
	// SUPERSEDED; a rollback is possible until the window ends (HR-519).
	RotationActivating RotationState = "ACTIVATING"
	// RotationAwaitingOldRemoval: the person deletes the old key on GitHub.
	RotationAwaitingOldRemoval RotationState = "AWAITING_OLD_REMOVAL"
	// RotationConfirming: the gateway signs a JWT with the old key under a
	// credential_rotation_confirm lease; GitHub must refuse it.
	RotationConfirming RotationState = "CONFIRMING"
	// RotationConfirmed: GitHub refused the old key, which is now REVOKED
	// (HR-520).
	RotationConfirmed RotationState = "CONFIRMED"
	// RotationFailed: the rotation ended before activation; the candidate
	// is REVOKED and the old key untouched.
	RotationFailed RotationState = "FAILED"
	// RotationRolledBack: the old key is ACTIVE again and the candidate
	// REVOKED.
	RotationRolledBack RotationState = "ROLLED_BACK"
)

// RotationStates lists every state.
var RotationStates = []RotationState{
	RotationRequested, RotationCandidateSealed, RotationTesting, RotationActivating, RotationAwaitingOldRemoval,
	RotationConfirming, RotationConfirmed, RotationFailed, RotationRolledBack,
}

// RollbackWindow bounds a rollback after activation (HR-519): it ends when
// confirmation starts or after this long, whichever comes first.
const RollbackWindow = 24 * time.Hour

// Finished reports a state a rotation never leaves.
func (s RotationState) Finished() bool {
	return s == RotationConfirmed || s == RotationFailed || s == RotationRolledBack
}

// Activated reports a state in which the candidate was activated.
func (s RotationState) Activated() bool {
	switch s {
	case RotationActivating, RotationAwaitingOldRemoval, RotationConfirming, RotationConfirmed, RotationRolledBack:
		return true
	}
	return false
}

// CanMoveRotation reports whether a rotation may move from -> to; the
// database trigger credential_rotations_forward holds to the same table.
func CanMoveRotation(from, to RotationState) bool {
	switch from {
	case RotationRequested:
		return to == RotationCandidateSealed || to == RotationFailed
	case RotationCandidateSealed:
		return to == RotationTesting || to == RotationFailed
	case RotationTesting:
		return to == RotationActivating || to == RotationFailed
	case RotationActivating:
		return to == RotationAwaitingOldRemoval || to == RotationRolledBack
	case RotationAwaitingOldRemoval:
		return to == RotationConfirming
	case RotationConfirming:
		return to == RotationConfirmed || to == RotationAwaitingOldRemoval
	}
	return false
}

// Rotation errors.
var (
	ErrRotationMove     = errors.New("credentials: the rotation cannot move there from its state")
	ErrRotationNotSafe  = errors.New("credentials: activation needs a passed target test and a step-up")
	ErrRollbackClosed   = errors.New("credentials: the rollback window is closed")
	ErrRotationNotDone  = errors.New("credentials: the old key is revoked only when GitHub refuses it")
	ErrRotationFinished = errors.New("credentials: the rotation is finished")
)

// Rotation is the part of a rotation its moves decide on.
type Rotation struct {
	State RotationState
	// TestPassedAt is when GitHub accepted the candidate in a target test;
	// zero until then.
	TestPassedAt time.Time
	// ActivatedAt and RollbackUntil are zero until activation.
	ActivatedAt, RollbackUntil time.Time
}

func (r *Rotation) move(to RotationState) error {
	if r.State.Finished() {
		return ErrRotationFinished
	}
	if !CanMoveRotation(r.State, to) {
		return ErrRotationMove
	}
	r.State = to
	return nil
}

// Seal records the sealed candidate.
func (r *Rotation) Seal() error { return r.move(RotationCandidateSealed) }

// StartTest leases the target test.
func (r *Rotation) StartTest() error { return r.move(RotationTesting) }

// Tested records a target test's result: a pass keeps the rotation in
// TESTING, ready for activation; a failure fails it.
func (r *Rotation) Tested(passed bool, at time.Time) error {
	if r.State != RotationTesting {
		return ErrRotationMove
	}
	if !passed {
		return r.move(RotationFailed)
	}
	r.TestPassedAt = at
	return nil
}

// Activate makes the candidate ACTIVE (HR-518): only after a passed target
// test and with a fresh step-up. The rollback window starts now.
func (r *Rotation) Activate(steppedUp bool, now time.Time) error {
	if r.State != RotationTesting {
		if r.State.Finished() {
			return ErrRotationFinished
		}
		return ErrRotationMove
	}
	if r.TestPassedAt.IsZero() || !steppedUp {
		return ErrRotationNotSafe
	}
	if err := r.move(RotationActivating); err != nil {
		return err
	}
	r.ActivatedAt, r.RollbackUntil = now, now.Add(RollbackWindow)
	return nil
}

// CanRollBack reports whether a rollback is possible at now (HR-519):
// while ACTIVATING and within the window.
func (r Rotation) CanRollBack(now time.Time) bool {
	return r.State == RotationActivating && !now.After(r.RollbackUntil)
}

// RollBack makes the old key ACTIVE again and the candidate REVOKED.
func (r *Rotation) RollBack(now time.Time) error {
	if r.State.Finished() {
		return ErrRotationFinished
	}
	if !r.CanRollBack(now) {
		return ErrRollbackClosed
	}
	return r.move(RotationRolledBack)
}

// CloseRollback ends the rollback window: when it passed, or when the
// person starts confirmation.
func (r *Rotation) CloseRollback() error { return r.move(RotationAwaitingOldRemoval) }

// StartConfirm leases the confirmation that GitHub refuses the old key.
// From ACTIVATING it closes the rollback window first.
func (r *Rotation) StartConfirm() error {
	if r.State == RotationActivating {
		if err := r.CloseRollback(); err != nil {
			return err
		}
	}
	return r.move(RotationConfirming)
}

// Confirmed records a confirmation: only GitHub's refusal of the old key
// confirms the rotation (HR-520); any other answer returns it to
// AWAITING_OLD_REMOVAL, and the old credential stays as it is.
func (r *Rotation) Confirmed(refused bool) error {
	if r.State != RotationConfirming {
		return ErrRotationMove
	}
	if !refused {
		return r.move(RotationAwaitingOldRemoval)
	}
	return r.move(RotationConfirmed)
}

// Probe results the gateway reports for a rotation lease: what GitHub
// answered for GET /app and for the installation read, signed with the
// candidate (test) or the old key (confirm).
type Probe struct {
	// AppStatus and InstallationStatus are the HTTP statuses; zero when
	// the call was not made or got no answer.
	AppStatus, InstallationStatus int
	// AppMatches: GET /app named the App the credential was sealed for.
	AppMatches bool
	// ActiveStatus and ActiveMatches are what GET /app answered, at the same
	// moment, for the ACTIVE (new) key during a confirmation: the control
	// that tells a deleted old key from a JWT GitHub refuses for any other
	// reason, such as a skewed clock (D274).
	ActiveStatus  int
	ActiveMatches bool
}

// TestPassed reports whether a target test passed: GitHub accepted the
// candidate as the App it was sealed for, and for the installation.
func (p Probe) TestPassed() bool {
	return p.AppStatus == http.StatusOK && p.AppMatches && p.InstallationStatus == http.StatusOK
}

// OldKeyRefused reports whether GitHub refused the old key (HR-520, D274):
// GET /app answered 401 for it while, at the same moment, it answered 200
// for the active key and named the App. Anything else (an acceptance, a
// refusal of both, a rate limit, an error, no answer) proves nothing, so
// the old credential is not revoked.
func (p Probe) OldKeyRefused() bool {
	return p.AppStatus == http.StatusUnauthorized && p.ActiveStatus == http.StatusOK && p.ActiveMatches
}

// TestRefused reports whether GitHub definitely refused a candidate (D274):
// 401, 403 or 404 for GET /app or the installation, or GET /app naming
// another App. No answer, a rate limit or a server error proves nothing:
// the rotation stays TESTING for another test.
func (p Probe) TestRefused() bool {
	refused := func(s int) bool {
		return s == http.StatusUnauthorized || s == http.StatusForbidden || s == http.StatusNotFound
	}
	return refused(p.AppStatus) || (p.AppStatus == http.StatusOK && !p.AppMatches) || refused(p.InstallationStatus)
}

// The fields a rotation lease's report carries (JSON pointers, as a
// verification report's fields are).
const (
	FieldAppStatus          = "/app"
	FieldAppMatches         = "/app_matches"
	FieldInstallationStatus = "/installation"
	FieldActiveStatus       = "/active_app"
	FieldActiveMatches      = "/active_app_matches"
)

// Fields is p as a report's fields.
func (p Probe) Fields() map[string]string {
	return map[string]string{
		FieldAppStatus: strconv.Itoa(p.AppStatus), FieldAppMatches: strconv.FormatBool(p.AppMatches),
		FieldInstallationStatus: strconv.Itoa(p.InstallationStatus),
		FieldActiveStatus:       strconv.Itoa(p.ActiveStatus), FieldActiveMatches: strconv.FormatBool(p.ActiveMatches),
	}
}

// ProbeOf reads a report's fields; anything missing or malformed reads as
// no answer, which passes no test and confirms nothing.
func ProbeOf(fields map[string]string) Probe {
	status := func(k string) int {
		n, err := strconv.Atoi(fields[k])
		if err != nil || n < 0 || n > 599 {
			return 0
		}
		return n
	}
	return Probe{
		AppStatus: status(FieldAppStatus), AppMatches: fields[FieldAppMatches] == "true", InstallationStatus: status(FieldInstallationStatus),
		ActiveStatus: status(FieldActiveStatus), ActiveMatches: fields[FieldActiveMatches] == "true",
	}
}

// RotationLease is a rotation lease's request as the claiming gateway
// reads it (D259): the rotation and the sealed credential to test (the
// candidate) or to confirm dead (the old key), in the same sealed form as
// the gateway's configuration and sealed to that gateway's broker key. The
// task row holds the rotation's id only (HR-061).
type RotationLease struct {
	Rotation   string             `json:"rotation"`
	Credential RotationCredential `json:"credential"`
	// Active is, for a confirmation, the id of the ACTIVE credential (the
	// rotation's new key, in the gateway's configuration) that GET /app is
	// also asked with, as the control (D274).
	Active string `json:"active,omitzero"`
}

// RotationCredential is the sealed credential of a rotation lease.
type RotationCredential struct {
	ID           string   `json:"id"`
	Version      int32    `json:"version"`
	BrokerKey    string   `json:"broker_key_id"`
	Sealed       []byte   `json:"sealed"`
	AllowedHosts []string `json:"allowed_hosts"`
	Header       string   `json:"header"`
	Scheme       string   `json:"scheme"`
	Kind         string   `json:"kind"`
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
)

var t0 = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// tested is a rotation whose candidate passed its target test.
func tested(t *testing.T) *domain.Rotation {
	t.Helper()
	r := &domain.Rotation{State: domain.RotationRequested}
	for _, step := range []func() error{r.Seal, r.StartTest, func() error { return r.Tested(true, t0) }} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// TestHR518_ActivationNeedsAPassedTestAndStepUp: activation needs a passed
// target test and a step-up; a failed test fails the rotation and leaves
// nothing to activate.
// Covers: F424
func TestHR518_ActivationNeedsAPassedTestAndStepUp(t *testing.T) {
	r := tested(t)
	if err := r.Activate(false, t0); !errors.Is(err, domain.ErrRotationNotSafe) || r.State != domain.RotationTesting {
		t.Fatalf("without step-up: %v, %s", err, r.State)
	}
	untested := &domain.Rotation{State: domain.RotationTesting}
	if err := untested.Activate(true, t0); !errors.Is(err, domain.ErrRotationNotSafe) {
		t.Fatalf("without a passed test: %v", err)
	}
	sealed := &domain.Rotation{State: domain.RotationCandidateSealed}
	if err := sealed.Activate(true, t0); !errors.Is(err, domain.ErrRotationMove) {
		t.Fatalf("before the test: %v", err)
	}
	failed := &domain.Rotation{State: domain.RotationTesting}
	if err := failed.Tested(false, t0); err != nil || failed.State != domain.RotationFailed {
		t.Fatalf("failed test: %v, %s", err, failed.State)
	}
	if err := failed.Activate(true, t0); !errors.Is(err, domain.ErrRotationFinished) {
		t.Fatalf("activate a failed rotation: %v", err)
	}
	if err := r.Activate(true, t0); err != nil || r.State != domain.RotationActivating || !r.RollbackUntil.Equal(t0.Add(24*time.Hour)) {
		t.Fatalf("activate: %v, %s, %v", err, r.State, r.RollbackUntil)
	}
}

// TestHR519_RollbackOnlyBeforeConfirmation: a rollback is possible only
// while ACTIVATING, within 24 hours of activation; once confirmation
// starts, or the window passes, it is refused.
// Covers: F424
func TestHR519_RollbackOnlyBeforeConfirmation(t *testing.T) {
	r := tested(t)
	if err := r.Activate(true, t0); err != nil {
		t.Fatal(err)
	}
	late := *r
	if err := late.RollBack(t0.Add(24*time.Hour + time.Second)); !errors.Is(err, domain.ErrRollbackClosed) {
		t.Fatalf("after the window: %v", err)
	}
	confirming := *r
	if err := confirming.StartConfirm(); err != nil || confirming.State != domain.RotationConfirming {
		t.Fatalf("start confirm: %v, %s", err, confirming.State)
	}
	if err := confirming.RollBack(t0.Add(time.Minute)); !errors.Is(err, domain.ErrRollbackClosed) {
		t.Fatalf("while confirming: %v", err)
	}
	awaiting := confirming
	if err := awaiting.Confirmed(false); err != nil || awaiting.State != domain.RotationAwaitingOldRemoval {
		t.Fatalf("not refused: %v, %s", err, awaiting.State)
	}
	if err := awaiting.RollBack(t0.Add(time.Minute)); !errors.Is(err, domain.ErrRollbackClosed) {
		t.Fatalf("after confirmation started once: %v", err)
	}
	if err := r.RollBack(t0.Add(24 * time.Hour)); err != nil || r.State != domain.RotationRolledBack {
		t.Fatalf("within the window: %v, %s", err, r.State)
	}
	if err := r.RollBack(t0.Add(time.Hour)); !errors.Is(err, domain.ErrRotationFinished) {
		t.Fatalf("roll back twice: %v", err)
	}
}

// TestHR520_OldKeyRevokedOnlyWhenRefused: only a 401 for the old key while
// the active key gets 200 for the App at the same moment confirms the
// rotation (D274); an acceptance, a rate limit, an error, no answer, or a
// 401 for both keys (a skewed clock) returns it to AWAITING_OLD_REMOVAL.
// Covers: F424
func TestHR520_OldKeyRevokedOnlyWhenRefused(t *testing.T) {
	for _, status := range []int{
		0, 200, 403, 404, 429,
		500, 502,
	} {
		p := domain.Probe{AppStatus: status, ActiveStatus: 200, ActiveMatches: true}
		if p.OldKeyRefused() {
			t.Fatalf("status %d counted as a refusal", status)
		}
		r := domain.Rotation{State: domain.RotationConfirming}
		if err := r.Confirmed(p.OldKeyRefused()); err != nil || r.State != domain.RotationAwaitingOldRemoval {
			t.Fatalf("status %d: %v, %s", status, err, r.State)
		}
	}
	for name, p := range map[string]domain.Probe{
		"both refused (a skewed clock)": {AppStatus: 401, ActiveStatus: 401},
		"no control":                    {AppStatus: 401},
		"the control names another App": {AppStatus: 401, ActiveStatus: 200},
		"the control rate limited":      {AppStatus: 401, ActiveStatus: 429, ActiveMatches: true},
	} {
		if p.OldKeyRefused() {
			t.Fatalf("%s counted as a refusal", name)
		}
	}
	r := domain.Rotation{State: domain.RotationConfirming}
	if err := r.Confirmed(domain.Probe{AppStatus: 401, ActiveStatus: 200, ActiveMatches: true}.OldKeyRefused()); err != nil || r.State != domain.RotationConfirmed {
		t.Fatalf("401: %v, %s", err, r.State)
	}
	early := domain.Rotation{State: domain.RotationAwaitingOldRemoval}
	if err := early.Confirmed(true); !errors.Is(err, domain.ErrRotationMove) {
		t.Fatalf("confirmed without a confirmation lease: %v", err)
	}
}

// TestT224_RotationMovesMatchTheSchema: the state machine allows exactly
// the moves migration 00239's trigger allows, and a finished rotation
// never moves (rotation lockout or rollback abuse).
// Covers: F424
func TestT224_RotationMovesMatchTheSchema(t *testing.T) {
	allowed := map[[2]domain.RotationState]bool{
		{domain.RotationRequested, domain.RotationCandidateSealed}:     true,
		{domain.RotationRequested, domain.RotationFailed}:              true,
		{domain.RotationCandidateSealed, domain.RotationTesting}:       true,
		{domain.RotationCandidateSealed, domain.RotationFailed}:        true,
		{domain.RotationTesting, domain.RotationActivating}:            true,
		{domain.RotationTesting, domain.RotationFailed}:                true,
		{domain.RotationActivating, domain.RotationAwaitingOldRemoval}: true,
		{domain.RotationActivating, domain.RotationRolledBack}:         true,
		{domain.RotationAwaitingOldRemoval, domain.RotationConfirming}: true,
		{domain.RotationConfirming, domain.RotationConfirmed}:          true,
		{domain.RotationConfirming, domain.RotationAwaitingOldRemoval}: true,
	}
	for _, from := range domain.RotationStates {
		for _, to := range domain.RotationStates {
			if got := domain.CanMoveRotation(from, to); got != allowed[[2]domain.RotationState{from, to}] {
				t.Errorf("%s -> %s: %v", from, to, got)
			}
			if from.Finished() && domain.CanMoveRotation(from, to) {
				t.Errorf("finished %s moves to %s", from, to)
			}
		}
	}
	if !(domain.Probe{AppStatus: 200, AppMatches: true, InstallationStatus: 200}).TestPassed() {
		t.Fatal("a 200/200 test did not pass")
	}
	for _, p := range []domain.Probe{{AppStatus: 200, AppMatches: true}, {AppStatus: 200, InstallationStatus: 200}, {AppMatches: true, InstallationStatus: 200}, {AppStatus: 401, AppMatches: true, InstallationStatus: 200}, {}} {
		if got := domain.ProbeOf(p.Fields()); got != p {
			t.Fatalf("fields round trip: %+v != %+v", got, p)
		}
		if p.TestPassed() {
			t.Fatalf("%+v passed", p)
		}
	}
}

// TestT224_ATestFailsOnlyOnADefiniteRefusal: 401, 403 or 404 for the App
// or the installation, or the App named wrongly, fail a candidate; no
// answer, a rate limit or a server error leave it for another test (D274).
// Covers: F424
func TestT224_ATestFailsOnlyOnADefiniteRefusal(t *testing.T) {
	for _, p := range []domain.Probe{
		{AppStatus: 401},
		{AppStatus: 403},
		{AppStatus: 404},
		{AppStatus: 200},
		{AppStatus: 200, AppMatches: true, InstallationStatus: 404},
		{AppStatus: 200, AppMatches: true, InstallationStatus: 403},
	} {
		if !p.TestRefused() || p.TestPassed() {
			t.Errorf("%+v is not a refusal", p)
		}
	}
	for _, p := range []domain.Probe{
		{},
		{AppStatus: 429},
		{AppStatus: 500},
		{AppStatus: 502},
		{AppStatus: 200, AppMatches: true},
		{AppStatus: 200, AppMatches: true, InstallationStatus: 429},
		{AppStatus: 200, AppMatches: true, InstallationStatus: 503},
	} {
		if p.TestRefused() {
			t.Errorf("%+v counted as a refusal", p)
		}
	}
}

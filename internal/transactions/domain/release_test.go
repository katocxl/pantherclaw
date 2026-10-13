// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// TestHR192_OnlyAnOpenUnknownOutcomeIsReleased: a resolved task, and a
// conflicting effect (whose budget stays committed), are never released.
func TestHR192_OnlyAnOpenUnknownOutcomeIsReleased(t *testing.T) {
	if err := domain.CheckReleasable(domain.KindUnknownOutcome, domain.TaskOpen); err != nil {
		t.Fatal(err)
	}
	for _, s := range []domain.TaskState{domain.TaskOccurred, domain.TaskNotOccurred} {
		if err := domain.CheckReleasable(domain.KindUnknownOutcome, s); !errors.Is(err, domain.ErrNotOpen) {
			t.Errorf("%s: %v", s, err)
		}
	}
	if err := domain.CheckReleasable(domain.KindConflictingEffect, domain.TaskOpen); !errors.Is(err, domain.ErrNotReleasable) {
		t.Fatalf("a conflicting effect: %v", err)
	}
}

// TestHR192_TheRunsOwnPeopleNeverRelease: the run's launcher, its
// represented principal and the agent's owner and backup owner are not
// independent; anyone else is.
func TestHR192_TheRunsOwnPeopleNeverRelease(t *testing.T) {
	p := domain.Party{Launcher: ids.NewV7(), Principal: ids.NewV7(), Owner: ids.NewV7(), BackupOwner: ids.NewV7()}
	for _, u := range []ids.UUID{p.Launcher, p.Principal, p.Owner, p.BackupOwner, {}} {
		if err := domain.CheckIndependent(u, p); !errors.Is(err, domain.ErrNotIndependent) {
			t.Errorf("%s: %v", u, err)
		}
	}
	if err := domain.CheckIndependent(ids.NewV7(), domain.Party{Launcher: ids.NewV7()}); err != nil {
		t.Fatal(err)
	}
}

// TestHR192_AReleaseLastsTheCeremonysFiveMinutes: the binding expires in
// whole seconds at most 5 minutes after it was made, and not at all after.
func TestHR192_AReleaseLastsTheCeremonysFiveMinutes(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 900_000_000, time.UTC)
	exp := domain.ReleaseExpiry(now)
	if !exp.Equal(time.Date(2026, 10, 10, 12, 5, 0, 0, time.UTC)) {
		t.Fatalf("expiry %s", exp)
	}
	if err := domain.CheckReleaseLive(exp, now); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{exp, exp.Add(time.Second)} {
		if err := domain.CheckReleaseLive(exp, at); !errors.Is(err, domain.ErrReleaseExpired) {
			t.Errorf("at %s: %v", at, err)
		}
	}
	if err := domain.CheckReleaseLive(time.Time{}, now); !errors.Is(err, domain.ErrReleaseExpired) {
		t.Fatal("a release without an expiry")
	}
}

// TestHR192_ShownEvidenceIsSortedOnce: the evidence a release names is the
// set of observations shown, in one order, so the binding does not depend
// on the order the page listed them in.
func TestHR192_ShownEvidenceIsSortedOnce(t *testing.T) {
	a, b := ids.NewV7(), ids.NewV7()
	if bytes.Compare(a[:], b[:]) > 0 {
		a, b = b, a
	}
	got := domain.ShownEvidence([]ids.UUID{b, a, b})
	if !slices.Equal(got, []ids.UUID{a, b}) {
		t.Fatalf("%v", got)
	}
	r1 := domain.Release{Reconciliation: a, Transaction: b, Basis: "x", Evidence: domain.ShownEvidence([]ids.UUID{b, a}), ExpiresAt: time.Now()}
	r2 := r1
	r2.Evidence = domain.ShownEvidence([]ids.UUID{a, b, a})
	b1, _ := r1.Binding()
	b2, _ := r2.Binding()
	if b1 != b2 {
		t.Fatal("the same evidence in another order gives another binding")
	}
	if len(domain.ShownEvidence(nil)) != 0 {
		t.Fatal("no evidence")
	}
}

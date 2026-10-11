// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
)

// TestHR211_EnforcedExpiresAndStaleReadsPartial: ENFORCED expires after 24
// hours by default, the expiry is configurable only within 1 to 168 hours
// (never "forever"), and a stale record reads PARTIAL (decision 3).
func TestHR211_EnforcedExpiresAndStaleReadsPartial(t *testing.T) {
	f, err := domain.NewFreshness(0, 0)
	if err != nil || f.EnforcedTTL != 24*time.Hour || f.ReassessEvery != time.Minute {
		t.Fatalf("defaults = %+v (%v), want 24h and 1m", f, err)
	}
	for _, ttl := range []time.Duration{-time.Hour, time.Minute, 59 * time.Minute, 169 * time.Hour, 1 << 62} {
		if _, err := domain.NewFreshness(ttl, 0); err == nil {
			t.Errorf("enforced_ttl %v accepted", ttl)
		}
	}
	for _, every := range []time.Duration{time.Second, 2 * time.Hour} {
		if _, err := domain.NewFreshness(0, every); err == nil {
			t.Errorf("reassess_every %v accepted", every)
		}
	}
	if f, err := domain.NewFreshness(time.Hour, 10*time.Second); err != nil || f.EnforcedTTL != time.Hour {
		t.Errorf("the lower bounds: %+v (%v)", f, err)
	}
	if domain.StaleState != domain.Partial {
		t.Errorf("stale state %v, want PARTIAL", domain.StaleState)
	}
}

func TestStateNamesRoundTrip(t *testing.T) {
	for _, s := range []domain.State{domain.Unknown, domain.ObserveOnly, domain.Partial, domain.Enforced} {
		if got, ok := domain.ParseState(s.String()); !ok || got != s {
			t.Errorf("%v round-trips to %v, %v", s, got, ok)
		}
	}
	if _, ok := domain.ParseState("PROTECTED"); ok {
		t.Error("an unknown state parsed")
	}
	if !slices.IsSorted([]domain.State{domain.Unknown, domain.ObserveOnly, domain.Partial, domain.Enforced}) {
		t.Error("states are not ordered weakest first")
	}
}

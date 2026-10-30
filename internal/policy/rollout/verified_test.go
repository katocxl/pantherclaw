// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rollout_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/policy/rollout"
)

// TestHR479_VerifiedThresholdCountsTargetsOtherThanException: a gated
// rollout completes only while VERIFIED targets are at least the
// threshold's share of every target that is not EXCEPTION, and never
// with no such target.
// Covers: F602
func TestHR479_VerifiedThresholdCountsTargetsOtherThanException(t *testing.T) {
	for _, c := range []struct {
		name    string
		counts  map[string]int64
		percent int32
		met     bool
	}{
		{"all verified", map[string]int64{rollout.TargetVerified: 4}, 100, true},
		{"one failed at 100", map[string]int64{rollout.TargetVerified: 3, rollout.TargetFailed: 1}, 100, false},
		{"exactly the share", map[string]int64{rollout.TargetVerified: 3, rollout.TargetAcknowledged: 1}, 75, true},
		{"just below", map[string]int64{rollout.TargetVerified: 2, rollout.TargetConfigured: 1}, 67, false},
		{"exceptions left out", map[string]int64{rollout.TargetVerified: 2, rollout.TargetException: 98}, 100, true},
		{"only exceptions", map[string]int64{rollout.TargetException: 5}, 1, false},
		{"no targets", map[string]int64{}, 1, false},
	} {
		if got := rollout.VerifiedThresholdMet(c.counts, c.percent); got != c.met {
			t.Errorf("%s: met %v, want %v", c.name, got, c.met)
		}
	}
}

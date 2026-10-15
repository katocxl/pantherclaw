// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package migrations

import (
	"slices"
	"testing"
)

// TestM11Rollout_KeepsEveryListerPurposeAndDownRestoresIt: 00111 adds
// policy_rollouts_due to every purpose 00087 (the latest lister before it)
// defined, and its Down migration restores 00087's lister exactly.
func TestM11Rollout_KeepsEveryListerPurposeAndDownRestoresIt(t *testing.T) {
	before := listerIn(t, "00087_coverage_invalidation.sql", "Up")
	after := listerIn(t, "00111_policy_rollouts.sql", "Up")
	if got, want := purposes(after), append(purposes(before), "policy_rollouts_due"); !slices.Equal(got, want) {
		t.Errorf("00111 lister purposes = %v, want %v", got, want)
	}
	if down := listerIn(t, "00111_policy_rollouts.sql", "Down"); down != before {
		t.Error("00111's Down migration does not restore the lister of 00087 exactly")
	}
}

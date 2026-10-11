// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package migrations

import (
	"slices"
	"testing"
)

// TestM9Coverage_KeepsEveryListerPurposeAndDownRestoresIt: 00087 adds
// coverage_reassess to every purpose 00072 (the latest lister before it)
// defined, and its Down migration restores 00072's lister exactly.
func TestM9Coverage_KeepsEveryListerPurposeAndDownRestoresIt(t *testing.T) {
	before := listerIn(t, "00072_retention.sql", "Up")
	after := listerIn(t, "00087_coverage_invalidation.sql", "Up")
	if got, want := purposes(after), append(purposes(before), "coverage_reassess"); !slices.Equal(got, want) {
		t.Errorf("00087 lister purposes = %v, want %v", got, want)
	}
	if down := listerIn(t, "00087_coverage_invalidation.sql", "Down"); down != before {
		t.Error("00087's Down migration does not restore the lister of 00072 exactly")
	}
}

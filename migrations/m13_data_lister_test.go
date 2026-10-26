// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package migrations

import (
	"slices"
	"testing"
)

// TestHR393_ListerAddsOrgsLapsedAndDownRestoresIt: 00178 adds orgs_lapsed
// to every purpose 00169 (the latest lister before it) defined, and its
// Down migration restores 00169's lister exactly.
func TestHR393_ListerAddsOrgsLapsedAndDownRestoresIt(t *testing.T) {
	before := listerIn(t, "00169_platform.sql", "Up")
	after := listerIn(t, "00178_lapse.sql", "Up")
	want := append(purposes(before), "orgs_lapsed")
	slices.Sort(want)
	got := purposes(after)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("00178 lister purposes = %v, want %v", got, want)
	}
	if down := listerIn(t, "00178_lapse.sql", "Down"); down != before {
		t.Error("00178's Down migration does not restore the lister of 00169 exactly")
	}
}

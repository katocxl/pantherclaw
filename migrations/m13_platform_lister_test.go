// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package migrations

import (
	"slices"
	"testing"
)

// TestHR373_ListerAddsOrgsAllAndDownRestoresIt: 00180 adds orgs_all to
// every purpose 00164 (the latest lister before it) defined, and its Down
// migration restores 00164's lister exactly.
func TestHR373_ListerAddsOrgsAllAndDownRestoresIt(t *testing.T) {
	before := listerIn(t, "00164_billing_links.sql", "Up")
	after := listerIn(t, "00180_platform.sql", "Up")
	want := append(purposes(before), "orgs_all")
	slices.Sort(want)
	got := purposes(after)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("00180 lister purposes = %v, want %v", got, want)
	}
	if down := listerIn(t, "00180_platform.sql", "Down"); down != before {
		t.Error("00180's Down migration does not restore the lister of 00164 exactly")
	}
}

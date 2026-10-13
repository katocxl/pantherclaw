// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package migrations

import (
	"slices"
	"testing"
)

// TestM7Retention_KeepsEveryListerPurposeAndDownRestoresIt: 00072 adds
// retention_due to every purpose 00070 (the latest lister on main) defined,
// and its Down migration restores 00070's lister exactly.
func TestM7Retention_KeepsEveryListerPurposeAndDownRestoresIt(t *testing.T) {
	before := listerIn(t, "00070_budget_settlement.sql", "Up")
	after := listerIn(t, "00072_retention.sql", "Up")
	if got, want := purposes(after), append(purposes(before), "retention_due"); !slices.Equal(got, want) {
		t.Errorf("00072 lister purposes = %v, want %v", got, want)
	}
	if down := listerIn(t, "00072_retention.sql", "Down"); down != before {
		t.Error("00072's Down migration does not restore the lister of 00070 exactly")
	}
}

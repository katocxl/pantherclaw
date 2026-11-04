// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "testing"

// TestThreatMapEditions: exports and API reads on Team and above, history on
// Business and above, none of the three on Community (G0 M28 D723).
// Covers: F968, F969, F970, F972, HR-686
func TestThreatMapEditions(t *testing.T) {
	for ed, want := range map[Edition][3]bool{
		Community:  {false, false, false},
		Team:       {true, false, true},
		Business:   {true, true, true},
		Enterprise: {true, true, true},
	} {
		e := Entitlements{Edition: ed}
		got := [3]bool{e.ThreatMapExport(), e.ThreatMapHistory(), e.ThreatMapAPIReads()}
		if got != want {
			t.Errorf("%s: export, history, api reads = %v, want %v", ed, got, want)
		}
	}
}

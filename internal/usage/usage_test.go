// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package usage

import (
	"testing"
	"time"
)

// TestWeeklyRecountIsSundayOffPeak: the recount runs every Sunday at 03:00
// UTC (D45).
func TestWeeklyRecountIsSundayOffPeak(t *testing.T) {
	sun := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC) // a Sunday
	for from, want := range map[time.Time]time.Time{
		time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC): sun,
		time.Date(2026, 10, 25, 2, 59, 0, 0, time.UTC): sun,
		sun: sun.AddDate(0, 0, 7),
		time.Date(2026, 10, 25, 4, 0, 0, 0, time.UTC): sun.AddDate(0, 0, 7),
	} {
		if got := (weeklyOffPeak{}).Next(from); !got.Equal(want) {
			t.Errorf("Next(%v) = %v, want %v", from, got, want)
		}
	}
}

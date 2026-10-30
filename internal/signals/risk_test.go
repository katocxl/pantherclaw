// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package signals

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestHR441_AFailedRiskWriteIsNoted: the event note says the identity-risk
// fact was not recorded, within the column's 200 characters.
// Covers: F366
func TestHR441_AFailedRiskWriteIsNoted(t *testing.T) {
	n := *noCaseNote(false)
	if !strings.Contains(n, RiskNotRecordedNote) || utf8.RuneCountInString(n) > 200 {
		t.Fatalf("note %q (%d)", n, utf8.RuneCountInString(n))
	}
	if *noCaseNote(true) != NoCaseNote {
		t.Fatal("a recorded risk changed the note")
	}
}

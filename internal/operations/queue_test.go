// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package operations

import "testing"

// An owned failure an automation raised queues as an automation exception
// (G0 M11 D38); every other owned failure stays a protection failure.
func TestFailureKind(t *testing.T) {
	for kind, want := range map[string]ItemKind{
		"automation.gate_stalled":   KindAutomationException,
		"automation.loop_stopped":   KindAutomationException,
		"reflex.edition_lapsed":     KindProtectionFailure,
		"automationx.not_one":       KindProtectionFailure,
		"exposure.recompute_lapsed": KindProtectionFailure,
	} {
		if got := failureKind(kind); got != want {
			t.Errorf("failureKind(%q) = %s, want %s", kind, got, want)
		}
	}
	if kindOrder[KindAutomationException] >= kindOrder[KindProtectionFailure] ||
		kindOrder[KindAutomationException] <= kindOrder[KindWaitingDecision] {
		t.Error("automation exceptions rank between protection failures and waiting decisions")
	}
}

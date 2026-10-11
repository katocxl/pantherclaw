// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"os"
	"strings"
	"testing"
)

// TestHR208_InitChangesNothingUntilConfirmed: init shows the diff and asks;
// no, or no answer at all, changes nothing; --yes changes without asking;
// and --dry-run with --yes is refused.
func TestHR208_InitChangesNothingUntilConfirmed(t *testing.T) {
	for _, answer := range []string{"n\n", "", "yes please\n"} {
		f := newInitFixture(t)
		f.answer = answer
		code, out, errs := f.run(t)
		if _, err := os.Stat(f.local()); code != 1 || err == nil || !strings.Contains(out, "+++ ") || !strings.Contains(out, "[y/N]") ||
			!strings.Contains(errs, "not confirmed") {
			t.Errorf("answer %q: %d %s %s", answer, code, out, errs)
		}
	}
	f := newInitFixture(t)
	f.answer = ""
	if code, out, errs := f.run(t, "--yes"); code != 0 || !hookRunsIn(t, f.local()) || strings.Contains(out, "[y/N]") {
		t.Errorf("--yes: %d %s %s", code, out, errs)
	}
	if code, _, _ := f.run(t, "--yes", "--dry-run"); code == 0 {
		t.Error("--yes with --dry-run")
	}
}

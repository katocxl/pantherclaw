// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// TestRange_Scenarios runs every scenario of redteam/scenarios through the
// range runner (HR-223, HR-226): each in a stack of its own, against the
// simulators only, and passes when every step observed what it expected.
// A scenario that needs the sandbox is skipped without the sandbox tag and
// PC_TEST_SANDBOX=1. `task range` is this test (EX-004's local gate).
func TestRange_Scenarios(t *testing.T) {
	set, err := app.LoadDir("../../redteam/scenarios")
	if err != nil {
		t.Fatal(err)
	}
	if len(set) < 30 {
		t.Fatalf("%d scenarios, want at least 30", len(set))
	}
	var results []domain.Result
	for _, l := range set {
		t.Run(l.Scenario.ID, func(t *testing.T) {
			d := newRangeDriver(t)
			r := &app.Runner{Driver: d, Timeout: 5 * time.Minute} // setup starts a whole stack
			res := r.Run(context.Background(), l.Scenario)
			results = append(results, res)
			switch res.Verdict {
			case domain.VerdictPass:
			case domain.VerdictSkipped:
				// Only a scenario that needs the sandbox may be skipped, and only
				// while there is none: a skip of anything else hides a regression.
				if slices.Contains(l.Scenario.Requires, "sandbox") && !sandboxBuilt {
					t.Skipf("%s: %s", l.Scenario.ID, res.Detail)
				}
				t.Errorf("%s SKIPPED: %s", l.Scenario.ID, res.Detail)
			default:
				t.Errorf("%s %s: %s", l.Scenario.ID, res.Verdict, res.Detail)
				for _, st := range res.Steps {
					t.Logf("  step %s: matched=%v expected %+v observed %s/%s/%s %v %s %s", st.StepID, st.Matched, st.Expect,
						st.Observed.Outcome, st.Observed.Reason, st.Observed.Code, st.Observed.Reasons, st.Observed.Detail+" "+firstN(st.Observed.Response, 400)+firstN([]byte(tail(st.Observed.Detail)), 900), st.Mismatch)
				}
			}
		})
	}
	if dir := os.Getenv("PC_RANGE_SUMMARY"); dir != "" {
		_ = os.WriteFile(dir, []byte(summary(results)), 0o600)
	}
}

func summary(results []domain.Result) string {
	out := ""
	for _, r := range results {
		out += string(r.Verdict) + " " + r.ScenarioID + " " + r.Detail + "\n"
	}
	return out
}

func firstN(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}

func tail(s string) string {
	if len(s) > 900 {
		return s[len(s)-900:]
	}
	return s
}

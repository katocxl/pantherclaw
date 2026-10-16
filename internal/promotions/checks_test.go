// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package promotions

import (
	"slices"
	"testing"
)

// TestPrefixesExpandToKnownOperations (D70): a prefix becomes every known
// operation under it, never a wider or sibling family; a prefix nothing is
// known under is reported.
func TestPrefixesExpandToKnownOperations(t *testing.T) {
	c := catalog{ops: []string{"github.pull.merge", "github.pull.read", "github.pullx.merge", "payments.refund.create"}}
	for _, tc := range []struct {
		ops, exact, empty []string
	}{
		{[]string{"github.pull.*"}, []string{"github.pull.merge", "github.pull.read"}, nil},
		{[]string{"github.*", "payments.refund.create"}, []string{"github.pull.merge", "github.pull.read", "github.pullx.merge", "payments.refund.create"}, nil},
		{[]string{"payments.charge.*", "payments.refund.create"}, []string{"payments.refund.create"}, []string{"payments.charge.*"}},
		{[]string{"shell.command.run"}, []string{"shell.command.run"}, nil},
	} {
		exact, empty := c.expand(tc.ops)
		if !slices.Equal(exact, tc.exact) || !slices.Equal(empty, tc.empty) {
			t.Errorf("expand(%v) = %v, %v; want %v, %v", tc.ops, exact, empty, tc.exact, tc.empty)
		}
	}
	if got := (catalog{}).under("github.*"); got != nil {
		t.Errorf("an empty catalog expands to %v", got)
	}
}

func TestNormalizeOperations(t *testing.T) {
	got, err := normalizeOperations([]string{"b.c", "a.*", "b.c"})
	if err != nil || !slices.Equal(got, []string{"a.*", "b.c"}) {
		t.Fatalf("got %v %v", got, err)
	}
	for _, bad := range [][]string{nil, {"*"}, {"Payments.refund"}, {"a.b*"}, {""}} {
		if _, err := normalizeOperations(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	many := make([]string, maxOperations+1)
	for i := range many {
		many[i] = "op.n" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	if _, err := normalizeOperations(many); err == nil {
		t.Error("more than the maximum accepted")
	}
}

// TestReadinessIsPerOperationAndComplete: an operation is ready only when
// every check ran and passed.
func TestReadinessIsPerOperationAndComplete(t *testing.T) {
	all := func(passed bool) []Check {
		var cs []Check
		for _, n := range CheckNames {
			cs = append(cs, Check{Name: n, Passed: passed})
		}
		return cs
	}
	if !(Readiness{Checks: all(true)}).Ready() {
		t.Error("all passed is not ready")
	}
	if (Readiness{Checks: all(true)[:5]}).Ready() {
		t.Error("a missing check is ready")
	}
	cs := all(true)
	cs[4].Passed = false
	r := Readiness{Checks: cs}
	if r.Ready() || !slices.Equal(r.Failed(), []string{CheckCoverage}) {
		t.Errorf("failed coverage: ready %v, failed %v", r.Ready(), r.Failed())
	}
	if c := declared(""); c.Passed {
		t.Error("an undeclared failure behavior passed")
	}
	if c := declared(Queue); !c.Passed {
		t.Error("QUEUE did not pass")
	}
}

// TestProvisionalOnlyWhenCoverageIsPending (D80): an operation is
// promotable provisionally only when every check but COVERAGE passed and
// COVERAGE is pending (no record), never when it failed on a record.
func TestProvisionalOnlyWhenCoverageIsPending(t *testing.T) {
	checks := func(coverage Check, others bool) Readiness {
		var cs []Check
		for _, n := range CheckNames {
			c := Check{Name: n, Passed: others}
			if n == CheckCoverage {
				c = coverage
			}
			cs = append(cs, c)
		}
		return Readiness{Checks: cs}
	}
	pendingCoverage := Check{Name: CheckCoverage, Pending: true}
	if r := checks(pendingCoverage, true); r.Ready() || !r.Provisional() {
		t.Error("pending coverage with every other check passed is not provisional")
	}
	if r := checks(Check{Name: CheckCoverage}, true); r.Provisional() {
		t.Error("a failing coverage record is provisional")
	}
	if r := checks(pendingCoverage, false); r.Provisional() {
		t.Error("pending coverage with another check failing is provisional")
	}
	if r := checks(Check{Name: CheckCoverage, Passed: true}, true); !r.Ready() || r.Provisional() {
		t.Error("everything passed is not ready, or is provisional")
	}
}

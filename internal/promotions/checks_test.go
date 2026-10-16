// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package promotions

import (
	"slices"
	"testing"
)

// TestUncoveredNeedsAnEqualOrCoveringEntry: an operation is promoted by
// the same entry or a prefix covering it; a narrower prefix never covers
// a wider one, and nothing covers an operation of another family.
func TestUncoveredNeedsAnEqualOrCoveringEntry(t *testing.T) {
	promoted := []string{"payments.refund.create", "github.pull.*"}
	for _, tc := range []struct {
		ops  []string
		want []string
	}{
		{[]string{"payments.refund.create"}, nil},
		{[]string{"github.pull.merge", "github.pull.*"}, nil},
		{[]string{"github.pull.review.*"}, nil},
		{[]string{"github.*"}, []string{"github.*"}},
		{[]string{"payments.refund.*"}, []string{"payments.refund.*"}},
		{[]string{"payments.refund.create", "payments.charge.create"}, []string{"payments.charge.create"}},
		{[]string{"github.pullx.merge"}, []string{"github.pullx.merge"}},
	} {
		if got := uncovered(tc.ops, promoted); !slices.Equal(got, tc.want) {
			t.Errorf("uncovered(%v) = %v, want %v", tc.ops, got, tc.want)
		}
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

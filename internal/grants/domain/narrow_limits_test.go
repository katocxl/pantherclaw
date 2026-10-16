// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"testing"
)

// TestNarrowLimits: a launch only lowers the ceiling's per-grant limits
// (G0 M11 part 2 D84 E7).
func TestNarrowLimits(t *testing.T) {
	base := Limits{
		Budgets:  []BudgetRule{{ID: "spend", Grouping: "task", Operations: Ops{"payments.*"}, Currency: "USD", Limit: "50.00", Period: "grant"}},
		Counters: []CountRule{{ID: "calls", Operations: Ops{"payments.*"}, Key: "task", Window: "1h", Max: "10"}},
	}
	got, err := NarrowLimits(base, Limits{})
	if err != nil || len(got.Budgets) != 1 || got.Budgets[0].Limit != "50.00" || got.Counters[0].Max != "10" {
		t.Fatalf("defaults: %+v %v", got, err)
	}
	lower := base.Budgets[0]
	lower.Limit = "20.00"
	fewer := base.Counters[0]
	fewer.Max = "3"
	got, err = NarrowLimits(base, Limits{Budgets: []BudgetRule{lower}, Counters: []CountRule{fewer}})
	if err != nil || got.Budgets[0].Limit != "20.00" || got.Counters[0].Max != "3" {
		t.Fatalf("narrowed: %+v %v", got, err)
	}
	higher := base.Budgets[0]
	higher.Limit = "80.00"
	reshaped := base.Budgets[0]
	reshaped.Operations = Ops{"payments.refund"}
	unset := base.Budgets[0]
	unset.Limit = ""
	more := base.Counters[0]
	more.Max = "11"
	for name, l := range map[string]Limits{
		"higher":    {Budgets: []BudgetRule{higher}},
		"reshaped":  {Budgets: []BudgetRule{reshaped}},
		"unset":     {Budgets: []BudgetRule{unset}},
		"new rule":  {Budgets: []BudgetRule{{ID: "other", Grouping: "task", Operations: Ops{"x.y"}, Currency: "USD", Limit: "1", Period: "grant"}}},
		"more runs": {Counters: []CountRule{more}},
	} {
		if _, err := NarrowLimits(base, l); !errors.Is(err, ErrOutside) {
			t.Errorf("%s: %v, want ErrOutside", name, err)
		}
	}
	if !base.CoversBudget("payments.refund") || base.CoversBudget("orders.cancel") {
		t.Error("CoversBudget")
	}
}

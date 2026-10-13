// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package retention

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR198_CategoryBoundsAndDefaults: the categories, limits and defaults
// of design decision 9.
func TestHR198_CategoryBoundsAndDefaults(t *testing.T) {
	want := map[Category]Bounds{
		Payloads:        {1, 30, 7},
		NormalizedFacts: {7, 730, 90},
		Receipts:        {30, 3650, 365},
		Approvals:       {365, 3650, 365},
		SecurityAudit:   {365, 3650, 365},
	}
	if len(Categories()) != len(want) {
		t.Fatalf("categories %v", Categories())
	}
	for _, c := range Categories() {
		b, ok := BoundsOf(c)
		if !ok || b != want[c] {
			t.Errorf("%s: bounds %+v, want %+v", c, b, want[c])
		}
		if !b.Allows(b.Default) || b.Allows(b.Min-1) || b.Allows(b.Max+1) {
			t.Errorf("%s: Allows is wrong at the edges", c)
		}
	}
	if _, ok := BoundsOf("versions"); ok {
		t.Error("versions are kept while referenced and have no period")
	}
}

// TestHR198_CurrentRevisionAndPendingShortening: a lengthening applies at
// once, a shortening only after its effective time, and a revision recorded
// before an earlier one took effect cancels it.
func TestHR198_CurrentRevisionAndPendingShortening(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	rev := func(n, days int, created, effective time.Time) Revision {
		return Revision{ID: ids.NewV7(), Category: Receipts, Number: n, Days: days, Created: created, Effective: effective}
	}
	r1 := rev(1, 365, t0, t0)
	r2 := rev(2, 30, t0.Add(10*day), t0.Add(17*day)) // a shortening
	type check struct {
		at            time.Time
		days, pending int
	}
	cases := []struct {
		name   string
		revs   []Revision
		checks []check
	}{
		{"default only", []Revision{r1}, []check{{t0, 365, 0}, {t0.Add(100 * day), 365, 0}}},
		{"a shortening takes effect 7 days later", []Revision{r1, r2}, []check{
			{t0.Add(10 * day), 365, 30}, {t0.Add(17*day - time.Second), 365, 30}, {t0.Add(17 * day), 30, 0},
		}},
		{"a lengthening cancels a pending shortening", []Revision{r1, r2, rev(3, 400, t0.Add(11*day), t0.Add(11*day))}, []check{
			{t0.Add(10 * day), 365, 30}, {t0.Add(11 * day), 400, 0}, {t0.Add(30 * day), 400, 0},
		}},
		{"a second shortening replaces the first", []Revision{r1, r2, rev(3, 100, t0.Add(11*day), t0.Add(18*day))}, []check{
			{t0.Add(11 * day), 365, 100}, {t0.Add(17 * day), 365, 100}, {t0.Add(18 * day), 100, 0},
		}},
		{"setting the current period again cancels the shortening", []Revision{r1, r2, rev(3, 365, t0.Add(12*day), t0.Add(12*day))}, []check{
			{t0.Add(12 * day), 365, 0}, {t0.Add(20 * day), 365, 0},
		}},
		{"a later revision after the shortening took effect", []Revision{r1, r2, rev(3, 60, t0.Add(20*day), t0.Add(20*day))}, []check{
			{t0.Add(18 * day), 30, 0}, {t0.Add(20 * day), 60, 0},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, ch := range tc.checks {
				cur, ok := Current(tc.revs, Receipts, ch.at)
				if !ok || cur.Days != ch.days {
					t.Errorf("at %s: current %d (%v), want %d", ch.at, cur.Days, ok, ch.days)
				}
				p, ok := Pending(tc.revs, Receipts, ch.at)
				if got := map[bool]int{true: p.Days}[ok]; got != ch.pending {
					t.Errorf("at %s: pending %d, want %d", ch.at, got, ch.pending)
				}
			}
		})
	}
	if _, ok := Current([]Revision{r1}, Approvals, t0); ok {
		t.Error("a category never recorded has no current revision")
	}
	if n := Next([]Revision{r1, r2}, Receipts); n != 3 {
		t.Errorf("Next = %d", n)
	}
	if n := Next(nil, Approvals); n != 1 {
		t.Errorf("Next of nothing = %d", n)
	}
	if l := r2.Label(); l != "receipts r2" {
		t.Errorf("Label = %q", l)
	}
}

func TestHR198_HoldRequestsAreChecked(t *testing.T) {
	id := ids.NewV7()
	start, end := time.Now(), time.Now().Add(time.Hour)
	ok := []HoldRequest{
		{Scope: ScopeOrg, Reason: "litigation"},
		{Scope: ScopeAgent, ID: &id, Reason: "r"},
		{Scope: ScopeRun, ID: &id, Reason: "r"},
		{Scope: ScopeTransaction, ID: &id, Reason: "r"},
		{Scope: ScopeTimeRange, Start: &start, End: &end, Reason: "r"},
	}
	for _, h := range ok {
		if err := h.check(); err != nil {
			t.Errorf("%+v: %v", h, err)
		}
	}
	long := make([]rune, MaxReason+1)
	for i := range long {
		long[i] = 'x'
	}
	bad := []HoldRequest{
		{Scope: "tenant", Reason: "r"},
		{Scope: ScopeOrg, ID: &id, Reason: "r"},
		{Scope: ScopeAgent, Reason: "r"},
		{Scope: ScopeRun, ID: &ids.UUID{}, Reason: "r"},
		{Scope: ScopeTransaction, ID: &id, Start: &start, End: &end, Reason: "r"},
		{Scope: ScopeTimeRange, Start: &end, End: &start, Reason: "r"},
		{Scope: ScopeTimeRange, Start: &start, Reason: "r"},
		{Scope: ScopeOrg},
		{Scope: ScopeOrg, Reason: string(long)},
	}
	for _, h := range bad {
		if err := h.check(); err == nil {
			t.Errorf("%+v was accepted", h)
		}
	}
}

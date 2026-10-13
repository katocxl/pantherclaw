// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"testing"
	"time"
)

func at(t *testing.T, zone, local string) time.Time {
	t.Helper()
	loc, err := time.LoadLocation(zone)
	if err != nil {
		t.Fatal(err)
	}
	v, err := time.ParseInLocation("2006-01-02 15:04", local, loc)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestHR207_WeeklyEntriesOpenInTheirTimeZone: a weekly entry opens on its
// day from its local start for its minutes, past midnight too, and a
// daylight-saving change does not stretch or shorten it.
func TestHR207_WeeklyEntriesOpenInTheirTimeZone(t *testing.T) {
	const zone = "Europe/London"
	w := Window{Environment: "production", TimeZone: zone, Weekly: []Weekly{
		{Day: "mon", Start: "09:00", Minutes: 8 * 60},
		{Day: "fri", Start: "22:00", Minutes: 4 * 60},
		{Day: "sun", Start: "00:30", Minutes: 120},
	}}
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	for local, want := range map[string]State{
		"2026-10-12 08:59": Closed, // Monday
		"2026-10-12 09:00": Open,
		"2026-10-12 16:59": Open,
		"2026-10-12 17:00": Closed,
		"2026-10-13 10:00": Closed, // Tuesday
		"2026-10-16 23:30": Open,   // Friday night
		"2026-10-17 01:59": Open,   // past midnight, Saturday
		"2026-10-17 02:00": Closed,
		// Clocks went forward at 01:00 on 29 March 2026: two hours from
		// 00:30 GMT end at 03:30 BST.
		"2026-03-29 03:15": Open,
		"2026-03-29 03:30": Closed,
	} {
		if got := w.At(at(t, zone, local)); got != want {
			t.Errorf("%s: %s, want %s", local, got, want)
		}
	}
}

// TestHR207_AFreezeOverridesEveryWindow: a freeze closes a weekly entry
// and a one-off window, and a one-off window opens outside the weekly
// entries.
func TestHR207_AFreezeOverridesEveryWindow(t *testing.T) {
	const zone = "UTC"
	freeze := Span{Start: at(t, zone, "2026-12-21 00:00"), End: at(t, zone, "2027-01-04 00:00")}
	w := Window{
		Environment: "production", TimeZone: zone,
		Weekly:  []Weekly{{Day: "tue", Start: "10:00", Minutes: 120}},
		OneOff:  []Span{{Start: at(t, zone, "2026-12-26 10:00"), End: at(t, zone, "2026-12-26 12:00")}, {Start: at(t, zone, "2026-11-07 10:00"), End: at(t, zone, "2026-11-07 11:00")}},
		Freezes: []Span{freeze},
	}
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	for local, want := range map[string]State{
		"2026-12-15 10:30": Open,   // a Tuesday before the freeze
		"2026-12-22 10:30": Frozen, // a Tuesday in it
		"2026-12-26 10:30": Frozen, // a one-off window in it
		"2026-11-07 10:30": Open,   // a one-off window on a Saturday
		"2026-11-07 11:00": Closed,
		"2027-01-05 10:30": Open,
	} {
		if got := w.At(at(t, zone, local)); got != want {
			t.Errorf("%s: %s, want %s", local, got, want)
		}
	}
}

// TestHR207_TheRepositoryWindowDecidesAndAnyFreezeHolds: a repository's
// own window decides for it, the environment's window for the rest, a
// freeze in either holds both, another environment's window does not
// count, and no window means NO_WINDOW.
func TestHR207_TheRepositoryWindowDecidesAndAnyFreezeHolds(t *testing.T) {
	const zone = "UTC"
	tuesday := at(t, zone, "2026-10-13 10:30")
	env := Window{Environment: "production", TimeZone: zone, Weekly: []Weekly{{Day: "tue", Start: "10:00", Minutes: 60}}}
	repo := Window{Environment: "production", Repository: "acme/payments", TimeZone: zone, Weekly: []Weekly{{Day: "wed", Start: "10:00", Minutes: 60}}}
	staging := Window{Environment: "staging", TimeZone: zone, Freezes: []Span{{Start: tuesday.Add(-time.Hour), End: tuesday.Add(time.Hour)}}}
	all := []Window{env, repo, staging}
	if got := Decide(all, "production", "acme/payments", tuesday); got != Closed {
		t.Errorf("the repository's window: %s", got)
	}
	if got := Decide(all, "production", "acme/web", tuesday); got != Open {
		t.Errorf("the environment's window: %s", got)
	}
	if got := Decide(all, "production", "acme/payments", tuesday.Add(24*time.Hour)); got != Open {
		t.Errorf("the repository's Wednesday: %s", got)
	}
	env.Freezes = []Span{{Start: tuesday.Add(-time.Hour), End: tuesday.Add(48 * time.Hour)}}
	if got := Decide([]Window{env, repo}, "production", "acme/payments", tuesday.Add(24*time.Hour)); got != Frozen {
		t.Errorf("an environment freeze over a repository window: %s", got)
	}
	if got := Decide(all, "staging", "acme/payments", tuesday); got != Frozen {
		t.Errorf("staging: %s", got)
	}
	if got := Decide(all, "canary", "acme/payments", tuesday); got != NoWindow {
		t.Errorf("no window: %s", got)
	}
}

// TestHR207_EnvironmentsMatchWhateverTheirCase: GitHub's environment names
// are case-insensitive, so a window is stored under its environment in
// lowercase and decides a release to that environment in any case, from
// either side.
func TestHR207_EnvironmentsMatchWhateverTheirCase(t *testing.T) {
	if got := NormalizeEnvironment("Production"); got != "production" {
		t.Fatalf("normalized %q", got)
	}
	const zone = "UTC"
	tuesday := at(t, zone, "2026-10-13 10:30")
	env := Window{Environment: "production", TimeZone: zone, Weekly: []Weekly{{Day: "tue", Start: "10:00", Minutes: 60}}}
	for _, name := range []string{"production", "Production", "PRODUCTION"} {
		if got := Decide([]Window{env}, name, "", tuesday); got != Open {
			t.Errorf("%s: %s", name, got)
		}
	}
	upper := env
	upper.Environment = "Production"
	upper.Freezes = []Span{{Start: tuesday.Add(-time.Hour), End: tuesday.Add(time.Hour)}}
	if got := Decide([]Window{upper}, "production", "", tuesday); got != Frozen {
		t.Errorf("a window named in another case: %s", got)
	}
}

func TestHR207_WindowsAreValidated(t *testing.T) {
	ok := Window{Environment: "production", TimeZone: "UTC", Weekly: []Weekly{{Day: "mon", Start: "09:00", Minutes: 60}}}
	start := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	for name, edit := range map[string]func(*Window){
		"no environment":   func(w *Window) { w.Environment = "" },
		"a control":        func(w *Window) { w.Environment = "prod\nuction" },
		"a repository":     func(w *Window) { w.Repository = "Acme/Payments" },
		"no time zone":     func(w *Window) { w.TimeZone = "" },
		"the local zone":   func(w *Window) { w.TimeZone = "Local" },
		"an unknown zone":  func(w *Window) { w.TimeZone = "Mars/Olympus" },
		"a day":            func(w *Window) { w.Weekly[0].Day = "monday" },
		"a start":          func(w *Window) { w.Weekly[0].Start = "24:00" },
		"no minutes":       func(w *Window) { w.Weekly[0].Minutes = 0 },
		"over a day":       func(w *Window) { w.Weekly[0].Minutes = MaxWeeklyMinutes + 1 },
		"nothing":          func(w *Window) { w.Weekly = nil },
		"a backward span":  func(w *Window) { w.OneOff = []Span{{Start: start, End: start}} },
		"a long freeze":    func(w *Window) { w.Freezes = []Span{{Start: start, End: start.Add(MaxSpan + time.Second)}} },
		"too many entries": func(w *Window) { w.Weekly = make([]Weekly, MaxEntries+1) },
	} {
		w := ok
		w.Weekly = append([]Weekly(nil), ok.Weekly...)
		edit(&w)
		if err := w.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
}

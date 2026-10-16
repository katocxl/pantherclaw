// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package cron

import (
	"errors"
	"testing"
	"time"
)

func zone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := LoadZone(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func utc(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestParseValid(t *testing.T) {
	t.Parallel()
	for _, expr := range []string{
		"* * * * *",
		"*/5 * * * *",
		"0,15,30,45 9-17 * * MON-FRI",
		"0 9 * * mon-fri",
		"0 0 1 jan,JUL *",
		"0 0 29 2 *",
		"0 9 * * 0",
		"0 9 * * 7",
		"0 9 * * 5-7",
		"10-50/10 */2 1-15/7 */3 *",
		"  0   0  1  1  *  ",
		"59 23 31 12 6",
	} {
		if _, err := Parse(expr); err != nil {
			t.Errorf("Parse(%q) = %v", expr, err)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		expr string
		want error
	}{
		{"", ErrSyntax},
		{"* * * *", ErrSyntax},
		{"* * * * * *", ErrSyntax},
		{"@daily", ErrSyntax},
		{"60 * * * *", ErrSyntax},
		{"* 24 * * *", ErrSyntax},
		{"* * 0 * *", ErrSyntax},
		{"* * 32 * *", ErrSyntax},
		{"* * * 0 *", ErrSyntax},
		{"* * * 13 *", ErrSyntax},
		{"* * * * 8", ErrSyntax},
		{"*/0 * * * *", ErrSyntax},
		{"*/61 * * * *", ErrSyntax},
		{"*/+5 * * * *", ErrSyntax},
		{"5/10 * * * *", ErrSyntax},
		{"5-1 * * * *", ErrSyntax},
		{"1,,2 * * * *", ErrSyntax},
		{"-1 * * * *", ErrSyntax},
		{"01 * * * *", ErrSyntax},
		{"* * * * MONDAY", ErrSyntax},
		{"* * * FEB-JAN *", ErrSyntax},
		{"* * * * L", ErrSyntax},
		{"0 0 ? * *", ErrSyntax},
		{"0 0 * * 1#2", ErrSyntax},
		{"0 0 30 2 *", ErrNeverFires},
		{"0 0 31 4,6,9,11 *", ErrNeverFires},
		{"0 0 30,31 FEB *", ErrNeverFires},
		{"0 0 1 1 * " + string(make([]byte, MaxLen)), ErrSyntax},
	} {
		if _, err := Parse(tc.expr); !errors.Is(err, tc.want) {
			t.Errorf("Parse(%q) = %v, want %v", tc.expr, err, tc.want)
		}
	}
}

// A day-of-week restriction makes an impossible day-of-month possible
// (the days are ORed).
func TestParseImpossibleDayWithWeekday(t *testing.T) {
	t.Parallel()
	s, err := Parse("0 0 30 2 MON")
	if err != nil {
		t.Fatal(err)
	}
	o, ok := s.Next(utc("2027-01-31T00:00:00Z"), time.UTC, GapSkip)
	if !ok || !o.At.Equal(utc("2027-02-01T00:00:00Z")) {
		t.Fatalf("got %v %v", o, ok)
	}
}

func TestDayOfWeekZeroAndSevenAreSunday(t *testing.T) {
	t.Parallel()
	from := utc("2027-06-01T00:00:00Z") // a Tuesday
	want := utc("2027-06-06T09:00:00Z") // the Sunday after
	for _, expr := range []string{"0 9 * * 0", "0 9 * * 7", "0 9 * * SUN", "0 9 * * sun", "0 9 * * 7-7"} {
		o, ok := MustParse(expr).Next(from, time.UTC, GapSkip)
		if !ok || !o.At.Equal(want) {
			t.Errorf("%q: got %v, want %v", expr, o.At, want)
		}
	}
	// 5-7 is Friday, Saturday and Sunday; "*" covers each day once.
	got := MustParse("0 9 * * 5-7").Preview(from, time.UTC, GapSkip, 4)
	wantDays := []time.Weekday{time.Friday, time.Saturday, time.Sunday, time.Friday}
	for i, o := range got {
		if o.At.Weekday() != wantDays[i] {
			t.Errorf("5-7 occurrence %d on %v, want %v", i, o.At.Weekday(), wantDays[i])
		}
	}
	all := MustParse("0 9 * * *").Preview(from, time.UTC, GapSkip, 7)
	for i := 1; i < len(all); i++ {
		if all[i].At.Sub(all[i-1].At) != 24*time.Hour {
			t.Fatalf("daily schedule not daily: %v", all)
		}
	}
}

func TestDayOfMonthOrDayOfWeek(t *testing.T) {
	t.Parallel()
	// Both restricted: the 13th or any Friday.
	got := MustParse("0 0 13 * FRI").Preview(utc("2027-08-01T00:00:00Z"), time.UTC, GapSkip, 6)
	want := []string{"2027-08-06", "2027-08-13", "2027-08-20", "2027-08-27", "2027-09-03", "2027-09-10"}
	for i, o := range got {
		if o.At.Format("2006-01-02") != want[i] {
			t.Errorf("occurrence %d = %s, want %s", i, o.At.Format("2006-01-02"), want[i])
		}
	}
	// "*/2" in day-of-week starts with "*": only day-of-month counts.
	o, _ := MustParse("0 0 13 * */2").Next(utc("2027-08-01T00:00:00Z"), time.UTC, GapSkip)
	if o.At.Format("2006-01-02") != "2027-08-13" {
		t.Errorf("*/2 day-of-week should not widen: %v", o.At)
	}
}

func TestLeapDays(t *testing.T) {
	t.Parallel()
	s := MustParse("0 12 29 2 *")
	for _, tc := range []struct{ from, want string }{
		{"2027-01-01T00:00:00Z", "2028-02-29T12:00:00Z"},
		{"2028-02-29T12:00:00Z", "2032-02-29T12:00:00Z"},
		{"2097-03-01T00:00:00Z", "2104-02-29T12:00:00Z"}, // 2100 is not a leap year
	} {
		o, ok := s.Next(utc(tc.from), time.UTC, GapSkip)
		if !ok || !o.At.Equal(utc(tc.want)) {
			t.Errorf("from %s: got %v %v, want %s", tc.from, o.At, ok, tc.want)
		}
	}
	// Feb 29 that must also be a Monday, with both days restricted, is ORed;
	// the 31st in a month list fires only in long months.
	o, _ := MustParse("0 0 31 * *").Next(utc("2027-04-01T00:00:00Z"), time.UTC, GapSkip)
	if !o.At.Equal(utc("2027-05-31T00:00:00Z")) {
		t.Errorf("31st: %v", o.At)
	}
}

func TestNextIsStrictlyAfter(t *testing.T) {
	t.Parallel()
	s := MustParse("0 * * * *")
	o, _ := s.Next(utc("2027-05-05T10:00:00Z"), time.UTC, GapSkip)
	if !o.At.Equal(utc("2027-05-05T11:00:00Z")) {
		t.Fatalf("got %v", o.At)
	}
	o, _ = s.Next(utc("2027-05-05T09:59:59.999Z"), time.UTC, GapSkip)
	if !o.At.Equal(utc("2027-05-05T10:00:00Z")) {
		t.Fatalf("got %v", o.At)
	}
}

// Brute force: in UTC every minute either matches or not.
func TestMatchesBruteForceUTC(t *testing.T) {
	t.Parallel()
	for _, expr := range []string{"*/7 */3 * * *", "5 4 1-10 * MON,WED", "0,30 0 * FEB-APR 1-5", "13 13 13 * *"} {
		s := MustParse(expr)
		from := utc("2027-01-27T00:00:00Z")
		var want []time.Time
		for m := 0; m < 60*24*120 && len(want) < 40; m++ {
			at := from.Add(time.Duration(m+1) * time.Minute)
			if s.hour.has(at.Hour()) && s.minute.has(at.Minute()) && s.dayMatches(at.Year(), at.Month(), at.Day()) {
				want = append(want, at)
			}
		}
		got := s.Preview(from, time.UTC, GapSkip, len(want))
		if len(got) != len(want) {
			t.Fatalf("%q: %d occurrences, want %d", expr, len(got), len(want))
		}
		for i := range want {
			if !got[i].At.Equal(want[i]) || got[i].Note != NoteNone || !got[i].Fires {
				t.Fatalf("%q #%d: %v, want %v", expr, i, got[i], want[i])
			}
		}
	}
}

func TestEuropeLondon(t *testing.T) {
	t.Parallel()
	lon := zone(t, "Europe/London")
	// Spring forward 2027-03-28 01:00 GMT -> 02:00 BST: 01:xx does not exist.
	daily := MustParse("30 1 * * *")
	o, _ := daily.Next(utc("2027-03-27T12:00:00Z"), lon, GapSkip)
	if !o.At.Equal(utc("2027-03-29T00:30:00Z")) || o.Note != NoteNone {
		t.Errorf("skip: %+v", o)
	}
	o, _ = daily.Next(utc("2027-03-27T12:00:00Z"), lon, GapShift)
	if !o.At.Equal(utc("2027-03-28T01:00:00Z")) || o.Note != NoteDSTShifted || o.Scheduled != "2027-03-28T01:30" {
		t.Errorf("shift: %+v", o)
	}
	if o.At.Format("15:04 MST") != "02:00 BST" {
		t.Errorf("shifted occurrence reads %s", o.At.Format("15:04 MST"))
	}
	// Several times in one gap shift to one firing.
	quarter := MustParse("*/15 1 * * *")
	got := quarter.Preview(utc("2027-03-28T00:00:00Z"), lon, GapShift, 2)
	if !got[0].At.Equal(utc("2027-03-28T01:00:00Z")) || !got[1].At.Equal(utc("2027-03-29T00:00:00Z")) {
		t.Errorf("collapsed shift: %+v", got)
	}
	// With SKIP the preview names every skipped time.
	got = quarter.Preview(utc("2027-03-28T00:00:00Z"), lon, GapSkip, 5)
	for i := 0; i < 4; i++ {
		if got[i].Fires || got[i].Note != NoteDSTSkipped || !got[i].At.IsZero() {
			t.Errorf("skip preview %d: %+v", i, got[i])
		}
	}
	if !got[4].Fires || !got[4].At.Equal(utc("2027-03-29T00:00:00Z")) {
		t.Errorf("after skips: %+v", got[4])
	}
	// Next ignores skipped times.
	o, _ = quarter.Next(utc("2027-03-28T00:00:00Z"), lon, GapSkip)
	if !o.At.Equal(utc("2027-03-29T00:00:00Z")) {
		t.Errorf("next with skip: %+v", o)
	}

	// Fall back 2027-10-31 02:00 BST -> 01:00 GMT: 01:xx happens twice and
	// fires once, at the first (BST) instant.
	o, _ = daily.Next(utc("2027-10-30T12:00:00Z"), lon, GapSkip)
	if !o.At.Equal(utc("2027-10-31T00:30:00Z")) || o.Note != NoteDSTRepeatedOnce {
		t.Errorf("repeated: %+v", o)
	}
	for _, after := range []string{"2027-10-31T00:30:00Z", "2027-10-31T01:00:00Z", "2027-10-31T01:29:00Z"} {
		o, _ = daily.Next(utc(after), lon, GapSkip)
		if !o.At.Equal(utc("2027-11-01T01:30:00Z")) || o.Note != NoteNone {
			t.Errorf("after %s: %+v (the second 01:30 must not fire)", after, o)
		}
	}
	// Hourly through the fall back: 01:00 fires once (00:00Z), 01:00Z does not.
	hourly := MustParse("0 * * * *").Preview(utc("2027-10-30T23:30:00Z"), lon, GapSkip, 3)
	want := []string{"2027-10-31T00:00:00Z", "2027-10-31T02:00:00Z", "2027-10-31T03:00:00Z"}
	for i, w := range want {
		if !hourly[i].At.Equal(utc(w)) {
			t.Errorf("hourly %d = %v, want %s", i, hourly[i].At.UTC(), w)
		}
	}
	if hourly[0].Note != NoteDSTRepeatedOnce || hourly[1].Note != NoteNone {
		t.Errorf("hourly notes: %+v", hourly)
	}
}

func TestAmericaNewYork(t *testing.T) {
	t.Parallel()
	ny := zone(t, "America/New_York")
	// 2027-03-14 02:00 EST -> 03:00 EDT.
	s := MustParse("30 2 * * *")
	o, _ := s.Next(utc("2027-03-13T12:00:00Z"), ny, GapSkip)
	if !o.At.Equal(utc("2027-03-15T06:30:00Z")) {
		t.Errorf("skip: %+v", o)
	}
	o, _ = s.Next(utc("2027-03-13T12:00:00Z"), ny, GapShift)
	if !o.At.Equal(utc("2027-03-14T07:00:00Z")) || o.Note != NoteDSTShifted || o.At.Format("15:04 MST") != "03:00 EDT" {
		t.Errorf("shift: %+v", o)
	}
	// 2027-11-07 02:00 EDT -> 01:00 EST: 01:30 fires once at EDT.
	o, _ = MustParse("30 1 * * *").Next(utc("2027-11-06T12:00:00Z"), ny, GapSkip)
	if !o.At.Equal(utc("2027-11-07T05:30:00Z")) || o.Note != NoteDSTRepeatedOnce {
		t.Errorf("repeated: %+v", o)
	}
	o, _ = MustParse("30 1 * * *").Next(utc("2027-11-07T05:30:00Z"), ny, GapSkip)
	if !o.At.Equal(utc("2027-11-08T06:30:00Z")) {
		t.Errorf("after repeated: %+v", o)
	}
	// 02:30 on the fall-back day exists once (EST).
	o, _ = s.Next(utc("2027-11-06T12:00:00Z"), ny, GapSkip)
	if !o.At.Equal(utc("2027-11-07T07:30:00Z")) || o.Note != NoteNone {
		t.Errorf("02:30 fall-back day: %+v", o)
	}
}

// Lord Howe shifts by 30 minutes: +10:30 standard, +11:00 daylight.
func TestAustraliaLordHowe(t *testing.T) {
	t.Parallel()
	lh := zone(t, "Australia/Lord_Howe")
	// 2027-10-03 02:00 +10:30 -> 02:30 +11:00: 02:00-02:29 do not exist.
	s := MustParse("15 2 * * *")
	o, _ := s.Next(utc("2027-10-02T00:00:00Z"), lh, GapSkip)
	if !o.At.Equal(utc("2027-10-03T15:15:00Z")) {
		t.Errorf("skip: %+v", o)
	}
	o, _ = s.Next(utc("2027-10-02T00:00:00Z"), lh, GapShift)
	if !o.At.Equal(utc("2027-10-02T15:30:00Z")) || o.Note != NoteDSTShifted || o.At.Format("15:04") != "02:30" {
		t.Errorf("shift: %+v (%s)", o, o.At.Format("15:04 -07:00"))
	}
	// 02:45 is after the gap and fires normally.
	o, _ = MustParse("45 2 * * *").Next(utc("2027-10-02T00:00:00Z"), lh, GapSkip)
	if !o.At.Equal(utc("2027-10-02T15:45:00Z")) || o.Note != NoteNone {
		t.Errorf("02:45: %+v", o)
	}
	// 2027-04-04 02:00 +11:00 -> 01:30 +10:30: 01:30-01:59 happen twice.
	o, _ = MustParse("45 1 * * *").Next(utc("2027-04-03T00:00:00Z"), lh, GapSkip)
	if !o.At.Equal(utc("2027-04-03T14:45:00Z")) || o.Note != NoteDSTRepeatedOnce {
		t.Errorf("repeated: %+v", o)
	}
	o, _ = MustParse("15 1 * * *").Next(utc("2027-04-03T00:00:00Z"), lh, GapSkip)
	if !o.At.Equal(utc("2027-04-03T14:15:00Z")) || o.Note != NoteNone {
		t.Errorf("01:15 before the repeat: %+v", o)
	}
	// Every 10 minutes through the repeat: 01:30, 01:40, 01:50 fire once each.
	got := MustParse("*/10 1-2 4 4 *").Preview(utc("2027-04-03T14:25:00Z"), lh, GapSkip, 5)
	want := []string{"2027-04-03T14:30:00Z", "2027-04-03T14:40:00Z", "2027-04-03T14:50:00Z", "2027-04-03T15:30:00Z", "2027-04-03T15:40:00Z"}
	for i, w := range want {
		if !got[i].At.Equal(utc(w)) {
			t.Errorf("repeat %d = %v (%s), want %s", i, got[i].At.UTC(), got[i].Scheduled, w)
		}
	}
}

func TestOccurrencesIncreaseAcrossZones(t *testing.T) {
	t.Parallel()
	for _, z := range []string{"Europe/London", "America/New_York", "Australia/Lord_Howe", "Asia/Kolkata", "Pacific/Chatham", "UTC"} {
		loc := zone(t, z)
		for _, expr := range []string{"*/10 * * * *", "30 1,2 * * *", "0 0 * * SUN"} {
			got := MustParse(expr).Preview(utc("2027-01-01T00:00:00Z"), loc, GapShift, 2000)
			for i := 1; i < len(got); i++ {
				if !got[i].At.After(got[i-1].At) {
					t.Fatalf("%s %q: %v then %v", z, expr, got[i-1], got[i])
				}
			}
		}
	}
}

func TestLoadZone(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", "Local", "Nowhere/Zone", "../../etc/passwd"} {
		if _, err := LoadZone(name); !errors.Is(err, ErrZone) {
			t.Errorf("LoadZone(%q) = %v", name, err)
		}
	}
	if _, err := LoadZone("Europe/London"); err != nil {
		t.Fatal(err)
	}
}

func TestPreviewCount(t *testing.T) {
	t.Parallel()
	s := MustParse("* * * * *")
	if got := s.Preview(utc("2027-01-01T00:00:00Z"), time.UTC, GapSkip, 0); got != nil {
		t.Fatalf("count 0: %v", got)
	}
	if got := s.Preview(utc("2027-01-01T00:00:00Z"), time.UTC, GapSkip, 50); len(got) != 50 {
		t.Fatalf("count 50: %d", len(got))
	}
}

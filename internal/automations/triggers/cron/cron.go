// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package cron parses the five-field schedules of automation triggers
// (G0 M11 part 2 D2, D17) and computes their occurrences in an IANA time
// zone. It is PantherClaw's own parser: no dependency, and the daylight
// saving rules are explicit.
//
// A schedule is "minute hour day-of-month month day-of-week". Each field is
// a comma-separated list of items; an item is "*", "*/step", "n", "a-b" or
// "a-b/step". Months accept JAN–DEC and days of the week SUN–SAT (case
// insensitive); day-of-week 0 and 7 are both Sunday, and SUN ending a range
// (MON-SUN, FRI-SUN) reads as 7. As in Vixie cron, when both day fields are
// restricted a day matches either of them; when one of them starts with "*"
// a day must match both (so "0 0 */2 * MON" is odd-numbered Mondays:
// Intersects reports that case, and previews say so).
//
// Wall-clock times are resolved in the zone:
//   - a time that does not exist (spring forward) is skipped (GapSkip) or
//     fires at the first valid instant after the gap (GapShift); several
//     skipped times in the same gap fire once;
//   - a time that occurs twice (fall back) fires once, at its first
//     instant.
package cron

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // the zone database on every platform, so a schedule means the same everywhere
)

// MaxLen bounds a schedule expression.
const MaxLen = 100

// Errors.
var (
	ErrSyntax     = errors.New("cron: a schedule is five fields: minute hour day-of-month month day-of-week")
	ErrNeverFires = errors.New("cron: the schedule never fires (no month has that day)")
	ErrZone       = errors.New("cron: unknown time zone")
)

// field is a set of allowed values, bit i = value i.
type field uint64

func (f field) has(v int) bool { return f&(1<<uint(v)) != 0 }

// Spec is a parsed schedule.
type Spec struct {
	expr                         string
	minute, hour, dom, month, dw field
	domStar, dowStar             bool
	// intersect: a stepped day field ("*/n") meets a restricted one.
	intersect bool
}

// String returns the expression as parsed.
func (s Spec) String() string { return s.expr }

type fieldDef struct {
	name     string
	min, max int
	names    map[string]int
}

var (
	monthNames = map[string]int{
		"JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6,
		"JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12,
	}
	dowNames = map[string]int{"SUN": 0, "MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6}

	defs = [5]fieldDef{
		{name: "minute", min: 0, max: 59},
		{name: "hour", min: 0, max: 23},
		{name: "day-of-month", min: 1, max: 31},
		{name: "month", min: 1, max: 12, names: monthNames},
		{name: "day-of-week", min: 0, max: 7, names: dowNames},
	}
)

// Parse parses a five-field schedule.
func Parse(expr string) (Spec, error) {
	if len(expr) > MaxLen {
		return Spec{}, fmt.Errorf("%w: longer than %d characters", ErrSyntax, MaxLen)
	}
	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return Spec{}, ErrSyntax
	}
	var fs [5]field
	for i, p := range parts {
		f, err := parseField(p, defs[i])
		if err != nil {
			return Spec{}, err
		}
		fs[i] = f
	}
	// Day-of-week 7 is Sunday.
	if fs[4].has(7) {
		fs[4] = (fs[4] &^ (1 << 7)) | 1
	}
	s := Spec{
		expr:    strings.Join(parts, " "),
		minute:  fs[0],
		hour:    fs[1],
		dom:     fs[2],
		month:   fs[3],
		dw:      fs[4],
		domStar: strings.HasPrefix(parts[2], "*"),
		dowStar: strings.HasPrefix(parts[4], "*"),
	}
	s.intersect = parts[2] != "*" && parts[4] != "*" && (s.domStar || s.dowStar)
	if !s.canFire() {
		return Spec{}, ErrNeverFires
	}
	return s, nil
}

// MustParse parses a schedule known to be valid (tests and built-ins).
func MustParse(expr string) Spec {
	s, err := Parse(expr)
	if err != nil {
		panic(err)
	}
	return s
}

func parseField(raw string, d fieldDef) (field, error) {
	bad := func(why string) error { return fmt.Errorf("%w: %s %q: %s", ErrSyntax, d.name, raw, why) }
	var out field
	for item := range strings.SplitSeq(raw, ",") {
		if item == "" {
			return 0, bad("empty list item")
		}
		rng, stepStr, hasStep := strings.Cut(item, "/")
		lo, hi := d.min, d.max
		switch {
		case rng == "*":
			if d.name == "day-of-week" {
				hi = 6 // "*" is every day once; 7 only as written
			}
		case strings.Contains(rng, "-"):
			a, b, _ := strings.Cut(rng, "-")
			var err error
			if lo, err = value(a, d); err != nil {
				return 0, bad(err.Error())
			}
			if hi, err = value(b, d); err != nil {
				return 0, bad(err.Error())
			}
			if d.name == "day-of-week" && hi == 0 && lo > 0 && strings.EqualFold(b, "SUN") {
				hi = 7 // SUN closing a range is the end of the week
			}
			if lo > hi {
				return 0, bad("a range runs from low to high")
			}
		default:
			if hasStep {
				return 0, bad("a step needs * or a range before it")
			}
			v, err := value(rng, d)
			if err != nil {
				return 0, bad(err.Error())
			}
			lo, hi = v, v
		}
		step := 1
		if hasStep {
			n, err := strconv.Atoi(stepStr)
			if err != nil || n < 1 || n > d.max-d.min+1 || stepStr != strconv.Itoa(n) {
				return 0, bad("the step must be a whole number from 1 to the field's span")
			}
			step = n
		}
		for v := lo; v <= hi; v += step {
			out |= 1 << uint(v)
		}
	}
	return out, nil
}

func value(s string, d fieldDef) (int, error) {
	if d.names != nil {
		if v, ok := d.names[strings.ToUpper(s)]; ok {
			return v, nil
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || s != strconv.Itoa(n) {
		return 0, fmt.Errorf("%q is not a value", s)
	}
	if n < d.min || n > d.max {
		return 0, fmt.Errorf("%d is outside %d-%d", n, d.min, d.max)
	}
	return n, nil
}

// maxDays is the longest each month can be (February in a leap year).
var maxDays = [13]int{0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

// canFire reports whether some real date matches. Only a day-of-month
// restriction without a day-of-week one can rule every date out (for
// example "0 0 30 2 *").
func (s Spec) canFire() bool {
	if !s.domStar && !s.dowStar {
		return true
	}
	for m := 1; m <= 12; m++ {
		if !s.month.has(m) {
			continue
		}
		for d := 1; d <= maxDays[m]; d++ {
			if s.dom.has(d) {
				return true
			}
		}
	}
	return false
}

// dayMatches applies the day-of-month / day-of-week rule to a civil date.
func (s Spec) dayMatches(y int, m time.Month, d int) bool {
	if !s.month.has(int(m)) {
		return false
	}
	wd := int(time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Weekday())
	domOK, dowOK := s.dom.has(d), s.dw.has(wd)
	if s.domStar || s.dowStar {
		return domOK && dowOK
	}
	return domOK || dowOK
}

// Intersects reports whether a stepped day field ("*/n") meets a
// restricted one, so a day must match both (Vixie cron): "0 0 */2 * MON"
// is odd-numbered Mondays, not odd days and Mondays.
func (s Spec) Intersects() bool { return s.intersect }

// Gap says what a wall-clock time inside a spring-forward gap does.
type Gap int

// Gap policies (D2 schedule.dst_gap).
const (
	GapSkip  Gap = iota // the occurrence does not happen (default)
	GapShift            // it happens at the first valid instant after the gap
)

// Note explains an occurrence (D17 PreviewSchedule).
type Note string

// Notes.
const (
	NoteNone            Note = "NONE"
	NoteDSTSkipped      Note = "DST_SKIPPED"
	NoteDSTShifted      Note = "DST_SHIFTED"
	NoteDSTRepeatedOnce Note = "DST_REPEATED_ONCE"
)

// Occurrence is one scheduled wall-clock time and what it does.
type Occurrence struct {
	// Scheduled is the wall-clock time the schedule names, in the zone
	// ("2006-01-02T15:04").
	Scheduled string
	// At is the instant it fires (zero when it is skipped), in the zone.
	At time.Time
	// Fires is false only for an occurrence skipped by GapSkip.
	Fires bool
	Note  Note
}

// LoadZone loads an IANA time zone. "Local" and "" are refused: a schedule
// names its zone.
func LoadZone(name string) (*time.Location, error) {
	if name == "" || name == "Local" || len(name) > 64 {
		return nil, ErrZone
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrZone, name)
	}
	return loc, nil
}

// searchDays bounds the search for the next matching day: 29 years cover a
// leap day on any day of the week (2100 is not a leap year).
const searchDays = 29*366 + 1

// Next returns the first occurrence that fires strictly after after.
func (s Spec) Next(after time.Time, loc *time.Location, gap Gap) (Occurrence, bool) {
	var found Occurrence
	ok := false
	s.walk(after, loc, gap, func(o Occurrence) bool {
		if !o.Fires {
			return true
		}
		found, ok = o, true
		return false
	})
	return found, ok
}

// Preview lists up to count occurrences after from, including the ones a
// gap skips (Fires false, Note DST_SKIPPED), so a person sees what the
// schedule will and will not do.
func (s Spec) Preview(from time.Time, loc *time.Location, gap Gap, count int) []Occurrence {
	if count <= 0 {
		return nil
	}
	out := make([]Occurrence, 0, count)
	s.walk(from, loc, gap, func(o Occurrence) bool {
		out = append(out, o)
		return len(out) < count
	})
	return out
}

// walk visits occurrences after after in order until visit returns false.
// It walks wall-clock times in the zone, resolves each to its instant, and
// keeps those strictly after after; skipped gap times are visited when
// their wall-clock time is after the wall-clock reading of after.
func (s Spec) walk(after time.Time, loc *time.Location, gap Gap, visit func(Occurrence) bool) {
	after = after.In(loc)
	startWall := civilOf(after)
	var last time.Time // the last fired instant, to collapse shifted times
	y, m, d := after.Date()
	for i := 0; i < searchDays; i++ {
		day := time.Date(y, m, d+i, 0, 0, 0, 0, time.UTC)
		dy, dm, dd := day.Date()
		if !s.dayMatches(dy, dm, dd) {
			continue
		}
		for h := 0; h < 24; h++ {
			if !s.hour.has(h) {
				continue
			}
			for mi := 0; mi < 60; mi++ {
				if !s.minute.has(mi) {
					continue
				}
				w := civil{dy, dm, dd, h, mi}
				if w != startWall && !w.after(startWall) {
					continue
				}
				o, emit := s.resolve(w, loc, gap, after, &last)
				if emit && !visit(o) {
					return
				}
			}
		}
	}
}

func (s Spec) resolve(w civil, loc *time.Location, gap Gap, after time.Time, last *time.Time) (Occurrence, bool) {
	o := Occurrence{Scheduled: w.String()}
	inst := instants(w, loc)
	switch len(inst) {
	case 0: // spring-forward gap
		if gap == GapSkip {
			if !w.after(civilOf(after)) {
				return o, false
			}
			o.Note = NoteDSTSkipped
			return o, true
		}
		t := gapEnd(w, loc)
		if !t.After(after) || t.Equal(*last) {
			return o, false
		}
		o.At, o.Fires, o.Note = t.In(loc), true, NoteDSTShifted
	default:
		t := inst[0]
		if !t.After(after) {
			return o, false
		}
		o.At, o.Fires, o.Note = t.In(loc), true, NoteNone
		if len(inst) > 1 {
			o.Note = NoteDSTRepeatedOnce
		}
	}
	*last = o.At
	return o, true
}

// civil is a wall-clock minute.
type civil struct {
	y      int
	m      time.Month
	d      int
	h, min int
}

func civilOf(t time.Time) civil {
	y, m, d := t.Date()
	return civil{y, m, d, t.Hour(), t.Minute()}
}

func (c civil) utc() time.Time { return time.Date(c.y, c.m, c.d, c.h, c.min, 0, 0, time.UTC) }

func (c civil) after(o civil) bool { return c.utc().After(o.utc()) }

func (c civil) String() string { return c.utc().Format("2006-01-02T15:04") }

// instants returns, in order, every instant whose wall-clock reading in loc
// is w: none in a gap, two in a repeated hour, otherwise one.
func instants(w civil, loc *time.Location) []time.Time {
	u := w.utc()
	var offsets []int
	for _, probe := range []time.Duration{-36 * time.Hour, 0, 36 * time.Hour} {
		_, off := u.Add(probe).In(loc).Zone()
		if !containsInt(offsets, off) {
			offsets = append(offsets, off)
		}
	}
	var out []time.Time
	for _, off := range offsets {
		t := u.Add(-time.Duration(off) * time.Second)
		if civilOf(t.In(loc)) == w && t.In(loc).Second() == 0 {
			out = append(out, t)
		}
	}
	// At most a handful of offsets: insertion sort, then drop duplicates.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Before(out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	uniq := out[:0]
	for _, t := range out {
		if len(uniq) == 0 || !uniq[len(uniq)-1].Equal(t) {
			uniq = append(uniq, t)
		}
	}
	return uniq
}

// gapEnd returns the first valid instant after the gap that swallows w: the
// transition itself.
func gapEnd(w civil, loc *time.Location) time.Time {
	u := w.utc()
	// Before the gap the wall clock runs behind; lo reads before w, hi after.
	lo, hi := u.Add(-36*time.Hour), u.Add(36*time.Hour)
	for hi.Sub(lo) > time.Second {
		mid := lo.Add(hi.Sub(lo) / 2).Truncate(time.Second)
		if civilOf(mid.In(loc)).after(w) || civilOf(mid.In(loc)) == w {
			hi = mid
		} else {
			lo = mid
		}
	}
	return hi
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

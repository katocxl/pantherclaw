// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds change windows (G0 M8 track P, HR-207): when a
// release approval for a deployment environment counts. A window has
// weekly entries in its time zone, one-off windows and freezes, for an
// environment and optionally one repository. A freeze overrides every
// window, and no configured window means no window: the release waits.
package domain

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // the zone database on every platform, so a window means the same everywhere
	"unicode"
)

// Weekly is a weekly entry: from Start (HH:MM, local time in the window's
// zone) on Day (mon … sun) for Minutes, possibly past midnight.
type Weekly struct {
	Day     string `json:"day"`
	Start   string `json:"start"`
	Minutes int    `json:"minutes"`
}

// Span is a one-off window or a freeze: from Start up to, not including,
// End.
type Span struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Contains reports whether t is in the span.
func (s Span) Contains(t time.Time) bool { return !t.Before(s.Start) && t.Before(s.End) }

// Window is a change window.
type Window struct {
	Environment string
	// Repository is owner/name, or "" for every repository.
	Repository string
	TimeZone   string
	Weekly     []Weekly
	OneOff     []Span
	Freezes    []Span
}

// Limits.
const (
	// MaxEntries is the most weekly entries, one-off windows or freezes.
	MaxEntries = 32
	// MaxWeeklyMinutes is the longest weekly entry: a day.
	MaxWeeklyMinutes = 24 * 60
	// MaxSpan is the longest one-off window or freeze.
	MaxSpan = 31 * 24 * time.Hour
)

var (
	// ErrInvalid: the window is not one PantherClaw stores.
	ErrInvalid = errors.New("releases: invalid change window")

	repoRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}/[a-z0-9._-]{1,100}$`)
	startRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)
	days    = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// ValidEnvironment reports whether s can name an environment: 1 to 100
// characters, no control characters.
func ValidEnvironment(s string) bool {
	return s != "" && len([]rune(s)) <= 100 && !strings.ContainsFunc(s, unicode.IsControl)
}

// ValidRepository reports whether s is "" or owner/name in lowercase.
func ValidRepository(s string) bool { return s == "" || repoRe.MatchString(s) }

// Validate checks a window before it is stored.
func (w Window) Validate() error {
	switch {
	case !ValidEnvironment(w.Environment):
		return invalid("the environment must be 1 to 100 characters without control characters")
	case !ValidRepository(w.Repository):
		return invalid("the repository must be owner/name in lowercase")
	case len(w.Weekly) > MaxEntries || len(w.OneOff) > MaxEntries || len(w.Freezes) > MaxEntries:
		return invalid("at most %d weekly entries, one-off windows and freezes each", MaxEntries)
	case len(w.Weekly) == 0 && len(w.OneOff) == 0 && len(w.Freezes) == 0:
		return invalid("a window needs a weekly entry, a one-off window or a freeze")
	}
	if _, err := w.location(); err != nil {
		return err
	}
	for _, e := range w.Weekly {
		if dayIndex(e.Day) < 0 || !startRe.MatchString(e.Start) || e.Minutes < 1 || e.Minutes > MaxWeeklyMinutes {
			return invalid("a weekly entry is a day (mon … sun), a start (HH:MM) and 1 to %d minutes", MaxWeeklyMinutes)
		}
	}
	for _, s := range append(append([]Span{}, w.OneOff...), w.Freezes...) {
		if s.Start.IsZero() || !s.End.After(s.Start) || s.End.Sub(s.Start) > MaxSpan {
			return invalid("a one-off window or freeze ends after it starts, at most %s later", MaxSpan)
		}
	}
	return nil
}

func (w Window) location() (*time.Location, error) {
	if w.TimeZone == "" || w.TimeZone == "Local" {
		return nil, invalid("the time zone must be an IANA name such as Europe/London or UTC")
	}
	loc, err := time.LoadLocation(w.TimeZone)
	if err != nil {
		return nil, invalid("unknown time zone %q", w.TimeZone)
	}
	return loc, nil
}

func dayIndex(d string) int {
	for i, x := range days {
		if x == d {
			return i
		}
	}
	return -1
}

// State is what windows say about an instant.
type State string

// States.
const (
	// Open: inside a one-off window or a weekly entry, and no freeze.
	Open State = "OPEN"
	// Closed: a window applies, and the instant is outside it.
	Closed State = "CLOSED"
	// Frozen: a freeze covers the instant.
	Frozen State = "FROZEN"
	// NoWindow: no window is configured, so a release cannot be approved.
	NoWindow State = "NO_WINDOW"
)

// At is the window's state at t.
func (w Window) At(t time.Time) State {
	for _, f := range w.Freezes {
		if f.Contains(t) {
			return Frozen
		}
	}
	for _, o := range w.OneOff {
		if o.Contains(t) {
			return Open
		}
	}
	loc, err := w.location()
	if err != nil {
		return Closed
	}
	local := t.In(loc)
	for _, e := range w.Weekly {
		m := startRe.FindStringSubmatch(e.Start)
		if m == nil {
			continue
		}
		h, _ := strconv.Atoi(m[1])
		mm, _ := strconv.Atoi(m[2])
		// The entry may have started today or, past midnight, yesterday.
		for back := range 2 {
			d := local.AddDate(0, 0, -back)
			if days[d.Weekday()] != e.Day {
				continue
			}
			start := time.Date(d.Year(), d.Month(), d.Day(), h, mm, 0, 0, loc)
			if (Span{Start: start, End: start.Add(time.Duration(e.Minutes) * time.Minute)}).Contains(t) {
				return Open
			}
		}
	}
	return Closed
}

// Decide is the state for a release to environment and repository at t,
// given the ACTIVE windows: a freeze in the environment's window or the
// repository's overrides both; otherwise the repository's own window
// decides when it has one, and the environment's window when not.
func Decide(windows []Window, environment, repository string, t time.Time) State {
	var env, repo *Window
	for i := range windows {
		switch w := &windows[i]; {
		case w.Environment != environment:
		case w.Repository == "":
			env = w
		case w.Repository == repository:
			repo = w
		}
	}
	for _, w := range []*Window{env, repo} {
		if w != nil && w.At(t) == Frozen {
			return Frozen
		}
	}
	switch {
	case repo != nil:
		return repo.At(t)
	case env != nil:
		return env.At(t)
	}
	return NoWindow
}

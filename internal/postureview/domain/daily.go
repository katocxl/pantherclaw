// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"cmp"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// DayKey is one row of a day's rollup (D206).
type DayKey struct {
	Kind     string
	Severity Severity
	Team     ids.UUID // the zero id: no team
}

// DayCount is a day's count for one key. Closed is nil when what closed
// cannot be known: the day before was not collected, or a source truncated
// (D257). It is never zero for that (HR-581).
type DayCount struct {
	DayKey
	Open   int
	Closed *int
}

func keyOf(f Finding) DayKey {
	k := DayKey{Kind: f.Kind, Severity: f.Severity}
	if f.TeamID != nil {
		k.Team = *f.TeamID
	}
	return k
}

// Rollup folds one day's open findings into counts. previous are the counts
// of the day before; closedKnown says whether both days' counts are whole.
// What closed is what was open yesterday plus what opened today less what is
// open now, for each key; a key that emptied keeps a row with zero open.
func Rollup(findings []Finding, day time.Time, previous []DayCount, closedKnown bool) []DayCount {
	open, opened := map[DayKey]int{}, map[DayKey]int{}
	end := day.Add(24 * time.Hour)
	for _, f := range findings {
		k := keyOf(f)
		open[k]++
		if !f.Since.Before(day) && f.Since.Before(end) {
			opened[k]++
		}
	}
	was := map[DayKey]int{}
	for _, p := range previous {
		was[p.DayKey] = p.Open
	}
	keys := map[DayKey]bool{}
	for k := range open {
		keys[k] = true
	}
	for k, n := range was {
		if n > 0 {
			keys[k] = true
		}
	}
	out := make([]DayCount, 0, len(keys))
	for k := range keys {
		c := DayCount{DayKey: k, Open: open[k]}
		if closedKnown {
			closed := max(0, was[k]+opened[k]-open[k])
			c.Closed = &closed
		}
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b DayCount) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Severity, b.Severity), cmp.Compare(a.Team.String(), b.Team.String()))
	})
	return out
}

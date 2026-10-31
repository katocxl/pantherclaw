// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"cmp"
	"slices"
	"strconv"
	"time"
)

// Rank reasons, in the order the keys apply.
const (
	ReasonSeverityPrefix    = "severity:"
	ReasonReachesProduction = "reaches_production"
	ReasonUnowned           = "unowned"
	ReasonAgePrefix         = "age_days:"
)

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// compare orders the more urgent first (D203): severity, reaching
// production, having no owner, age, then the stable id. It compares the keys
// one by one: nothing is summed or weighed.
func compare(a, b Finding) int {
	return cmp.Or(
		-cmp.Compare(a.Severity.Rank(), b.Severity.Rank()),
		-cmp.Compare(boolRank(a.ReachesProduction), boolRank(b.ReachesProduction)),
		-cmp.Compare(boolRank(a.Unowned), boolRank(b.Unowned)),
		a.Since.Compare(b.Since),
		cmp.Compare(a.Key(), b.Key()),
	)
}

// Rank orders findings already normalized and filtered to what the viewer
// may read, and states for each which keys applied. now is the read's clock.
func Rank(findings []Finding, now time.Time) []RankedFinding {
	sorted := slices.Clone(findings)
	slices.SortFunc(sorted, compare)
	out := make([]RankedFinding, 0, len(sorted))
	for _, f := range sorted {
		out = append(out, RankedFinding{Finding: f, OWASP: OWASP(f.Kind), RankReasons: reasons(f, now)})
	}
	return out
}

func reasons(f Finding, now time.Time) []string {
	out := []string{ReasonSeverityPrefix + string(f.Severity)}
	if f.ReachesProduction {
		out = append(out, ReasonReachesProduction)
	}
	if f.Unowned {
		out = append(out, ReasonUnowned)
	}
	if !f.Since.IsZero() && now.After(f.Since) {
		out = append(out, ReasonAgePrefix+strconv.Itoa(int(now.Sub(f.Since).Hours()/24)))
	}
	return out
}

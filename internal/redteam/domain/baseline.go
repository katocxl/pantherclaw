// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "sort"

// VerdictMissing is a baseline scenario with no current result.
const VerdictMissing Verdict = "MISSING"

// Entry is one scenario's verdict in a run or a baseline.
type Entry struct {
	ID      string
	Digest  string
	Verdict Verdict
}

// Regression is a scenario that passed in the baseline and does not now.
type Regression struct {
	ID  string
	Now Verdict // FAIL, ERROR, SKIPPED or MISSING
}

// Comparison is the outcome of the baseline gate (HR-226).
type Comparison struct {
	Regressions []Regression
	Failures    []string // current FAIL verdicts
	Errors      []string // current ERROR verdicts: the gate fails closed
	Changed     []string // scenarios whose digest differs from the baseline (reported, still compared)
}

// Compare checks a current run against a verified baseline. A regression is a
// baseline PASS that is now FAIL, ERROR, SKIPPED or absent; a changed digest
// is reported but the scenario is compared anyway.
func Compare(baseline, current []Entry) Comparison {
	cur := make(map[string]Entry, len(current))
	for _, e := range current {
		cur[e.ID] = e
	}
	var c Comparison
	for _, b := range baseline {
		now, ok := cur[b.ID]
		if ok && now.Digest != b.Digest {
			c.Changed = append(c.Changed, b.ID)
		}
		if b.Verdict != VerdictPass {
			continue
		}
		switch {
		case !ok:
			c.Regressions = append(c.Regressions, Regression{ID: b.ID, Now: VerdictMissing})
		case now.Verdict != VerdictPass:
			c.Regressions = append(c.Regressions, Regression{ID: b.ID, Now: now.Verdict})
		}
	}
	for _, e := range current {
		if e.Verdict == VerdictFail {
			c.Failures = append(c.Failures, e.ID)
		}
		if e.Verdict == VerdictError {
			c.Errors = append(c.Errors, e.ID)
		}
	}
	sort.Slice(c.Regressions, func(i, j int) bool { return c.Regressions[i].ID < c.Regressions[j].ID })
	sort.Strings(c.Failures)
	sort.Strings(c.Errors)
	sort.Strings(c.Changed)
	return c
}

// ExitCode is the gate's exit status: 0 with no FAIL, no ERROR and no regression, else 1.
func (c Comparison) ExitCode() int {
	if len(c.Regressions) > 0 || len(c.Failures) > 0 || len(c.Errors) > 0 {
		return 1
	}
	return 0
}

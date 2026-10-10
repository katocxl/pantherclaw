// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package replay

import (
	"cmp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
)

// differences lists, per check, the items that differ between the original
// checklist and the replayed one, with the policy rules among them and the
// inputs that explain them (F506). Which item is decisive follows from the
// items, so it is not compared. When the receipt left passed items out to
// fit, only the others are compared.
func differences(orig Original, replayed []pipeline.Item, lims []Limitation, change string) []Difference {
	trimmed := orig.Omitted > 0
	byStep := func(items []pipeline.Item) map[int][]pipeline.Item {
		out := map[int][]pipeline.Item{}
		for _, it := range items {
			if trimmed && (it.Status == pipeline.StatusPassed || it.Status == pipeline.StatusNotApplicable) {
				continue
			}
			it.Decisive = false
			out[it.Step] = append(out[it.Step], it)
		}
		for step := range out {
			slices.SortFunc(out[step], compareItems)
		}
		return out
	}
	a, b := byStep(orig.Checklist), byStep(replayed)
	var out []Difference
	for step := pipeline.StepScope; step <= pipeline.StepFinalBinding; step++ {
		x, y := a[step], b[step]
		if slices.EqualFunc(x, y, func(p, q pipeline.Item) bool { return compareItems(p, q) == 0 }) {
			continue
		}
		d := Difference{Step: step, Check: checkOf(x, y), Original: nonNil(x), Replayed: nonNil(y), Rules: rules(x, y)}
		if change != "" && (len(d.Rules) > 0 || step == pipeline.StepFacts) {
			d.Inputs = append(d.Inputs, change)
		}
		for _, l := range lims {
			if l.Step == step {
				d.Inputs = append(d.Inputs, l.Detail)
			}
		}
		if step == pipeline.StepFinalBinding && len(x) > 0 {
			d.Inputs = append(d.Inputs, "the final binding (step 9) changed the original decision; a replay runs steps 1 to 8 only")
		}
		out = append(out, d)
	}
	return out
}

func compareItems(p, q pipeline.Item) int {
	return cmp.Or(cmp.Compare(p.Status, q.Status), cmp.Compare(p.Code, q.Code), cmp.Compare(p.Level, q.Level),
		cmp.Compare(p.Detail, q.Detail), cmp.Compare(p.Check, q.Check))
}

func checkOf(x, y []pipeline.Item) string {
	for _, it := range slices.Concat(x, y) {
		return it.Check
	}
	return ""
}

func nonNil(items []pipeline.Item) []pipeline.Item {
	if items == nil {
		return []pipeline.Item{}
	}
	return items
}

// rules returns the ids of the policy rules among the items found on one
// side only; a policy item's level is "policy <version> rule <id>".
func rules(x, y []pipeline.Item) []string {
	only := func(a, b []pipeline.Item) []pipeline.Item {
		var out []pipeline.Item
		for _, it := range a {
			if !slices.ContainsFunc(b, func(o pipeline.Item) bool { return compareItems(it, o) == 0 }) {
				out = append(out, it)
			}
		}
		return out
	}
	var out []string
	for _, it := range slices.Concat(only(x, y), only(y, x)) {
		if !strings.HasPrefix(it.Level, "policy ") {
			continue
		}
		if _, id, ok := strings.Cut(it.Level, " rule "); ok && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

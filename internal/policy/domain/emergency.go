// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "slices"

// IsEmergency reports whether r is an emergency rule (Rule.Emergency;
// M11.1 D4, D24, HR-236).
func (r *Rule) IsEmergency() bool { return r.Emergency }

// CarryEmergency returns target with every emergency rule of current
// carried forward, each replacing a target rule with the same id, and the
// carried ids in current's order (M11.1 D4, F207). A rollback always
// carries, so it can never silently drop a rule added during an incident.
// The tests of current whose expect.rule names a carried rule follow their
// rule (D35), each replacing a target test with the same id, so the carried
// rule's mutants are still killed and the result passes its own gate; the
// returned ids name the carried rules only. Test bounds still apply: more
// than MaxTests is refused by Validate and the gate (TESTS_TOO_LARGE).
// Neither input is modified; a nil current carries nothing.
func CarryEmergency(current, target *Bundle) (*Bundle, []string) {
	out := *target
	out.Rules = slices.Clone(target.Rules)
	out.Tests = slices.Clone(target.Tests)
	if current == nil {
		return &out, nil
	}
	var carried []string
	for _, r := range current.Rules {
		if !r.IsEmergency() {
			continue
		}
		carried = append(carried, r.ID)
		if i := slices.IndexFunc(out.Rules, func(t Rule) bool { return t.ID == r.ID }); i >= 0 {
			out.Rules[i] = r
		} else {
			out.Rules = append(out.Rules, r)
		}
	}
	for _, tc := range current.Tests {
		if tc.Expect.Rule == "" || !slices.Contains(carried, tc.Expect.Rule) {
			continue
		}
		if i := slices.IndexFunc(out.Tests, func(t TestCase) bool { return t.ID == tc.ID }); i >= 0 {
			out.Tests[i] = tc
		} else {
			out.Tests = append(out.Tests, tc)
		}
	}
	return &out, carried
}

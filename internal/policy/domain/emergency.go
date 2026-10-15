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
	return &out, carried
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package celenv_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

// TestHR714_TriggerRulesReportNarrowing: a conjunct that does not test the
// rule id narrows the trigger, inside an || branch too; a filter that tests
// only the rule id does not (G0 M30 D948, F-M28-1).
//
// Covers: HR-714
func TestHR714_TriggerRulesReportNarrowing(t *testing.T) {
	for where, want := range map[string]bool{
		`event.attrs["rule"] == "pc.a"`:                                                         false,
		`event.attrs["rule"] in ["pc.a", "pc.b"] && event.attrs["rule"] == "pc.a"`:              false,
		`event.attrs["rule"] == "pc.a" || event.attrs["rule"] == "pc.b"`:                        false,
		`event.attrs["severity"] == "HIGH" && event.attrs["rule"] == "pc.a"`:                    true,
		`event.attrs["rule"] == "pc.a" && event.attrs["severity"] == "HIGH"`:                    true,
		`event.attrs["rule"] == "pc.a" || (event.attrs["rule"] == "pc.b" && event.kind == "x")`: true,
	} {
		ids, narrowed := celenv.TriggerRulesNarrowed(where)
		if len(ids) == 0 || narrowed != want {
			t.Errorf("%s: %v narrowed=%v, want %v", where, ids, narrowed, want)
		}
		if !slices.Equal(ids, celenv.TriggerRules(where)) {
			t.Errorf("%s: the two forms name different rules", where)
		}
	}
	// A filter that names no rule reports no narrowing either.
	if ids, narrowed := celenv.TriggerRulesNarrowed(`event.attrs["severity"] == "HIGH"`); ids != nil || narrowed {
		t.Errorf("no rule: %v %v", ids, narrowed)
	}
}

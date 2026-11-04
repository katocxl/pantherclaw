// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package celenv_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

// TestHR680_TriggerRulesReadsOnlyTopLevelRuleLiterals: an automation's
// trigger names rule ids only through a top-level conjunct
// event.attrs["rule"] in [...] or == "..."; any other shape names none
// (G0 M28 D713).
// Covers: F960, HR-680
func TestHR680_TriggerRulesReadsOnlyTopLevelRuleLiterals(t *testing.T) {
	for where, want := range map[string][]string{
		`event.attrs["rule"] in ["pc.b", "pc.a"]`:                              {"pc.a", "pc.b"},
		`event.attrs["rule"] == "pc.a"`:                                        {"pc.a"},
		`event.attrs["severity"] == "HIGH" && event.attrs["rule"] in ["pc.a"]`: {"pc.a"},
		`event.attrs["rule"] == "pc.a" || event.attrs["rule"] == "pc.b"`:       nil,
		`!(event.attrs["rule"] == "pc.a")`:                                     nil,
		`event.attrs["rule"].startsWith("pc.")`:                                nil,
		`event.attrs["rule"] in [event.attrs["x"]]`:                            nil,
		`other.attrs["rule"] == "pc.a"`:                                        nil,
		`event.attrs["kind"] == "pc.a"`:                                        nil,
		`event.attrs["rule"] in`:                                               nil,
		``:                                                                     nil,
	} {
		if got := celenv.TriggerRules(where); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", where, got, want)
		}
	}
}

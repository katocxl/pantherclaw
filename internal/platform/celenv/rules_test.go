// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package celenv_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

// TestHR680_TriggerRulesNeverOverClaim: an automation's trigger names the
// rule ids it can fire on: rule tests intersect across &&, ignoring a
// conjunct that does not touch the rule id, and unite across ||; anything
// it cannot analyze names no rule (G0 M28 D713, D720b L2).
// Covers: F960, HR-680
func TestHR680_TriggerRulesNeverOverClaim(t *testing.T) {
	for where, want := range map[string][]string{
		`event.attrs["rule"] in ["pc.b", "pc.a"]`:                              {"pc.a", "pc.b"},
		`event.attrs["rule"] == "pc.a"`:                                        {"pc.a"},
		`event.attrs["severity"] == "HIGH" && event.attrs["rule"] in ["pc.a"]`: {"pc.a"},
		// D720b L2: intersect across &&.
		`event.attrs["rule"] in ["a", "b"] && event.attrs["rule"] == "b"`:                                 {"b"},
		`event.attrs["rule"] == "a" && event.attrs["rule"] == "b"`:                                        nil,
		`event.kind == "alert" && (event.attrs["rule"] in ["a", "b"] && true)`:                            {"a", "b"},
		`event.attrs["rule"] == "pc.a" || event.attrs["rule"] == "pc.b"`:                                  {"pc.a", "pc.b"},
		`(event.attrs["rule"] == "a" || event.attrs["rule"] == "b") && event.attrs["rule"] in ["b", "c"]`: {"b"},
		// A branch that fires on any rule, or one not analyzed: none.
		`event.attrs["severity"] == "HIGH" || event.attrs["rule"] == "pc.a"`:        nil,
		`event.attrs["rule"] in ["a", "b"] && !(event.attrs["rule"] == "a")`:        nil,
		`event.attrs["rule"] in ["a", "b"] && event.attrs.rule == "a"`:              nil,
		`event.attrs["rule"] in ["a", "b"] && event.attrs[event.attrs["k"]] == "a"`: nil,
		`event.attrs["rule"] in ["a"] && size(event.attrs) > 1`:                     nil,
		`!(event.attrs["rule"] == "pc.a")`:                                          nil,
		`event.attrs["rule"].startsWith("pc.")`:                                     nil,
		`event.attrs["rule"] in [event.attrs["x"]]`:                                 nil,
		`other.attrs["rule"] == "pc.a"`:                                             nil,
		`event.attrs["kind"] == "pc.a"`:                                             nil,
		`event.attrs["rule"] in`:                                                    nil,
		``:                                                                          nil,
	} {
		if got := celenv.TriggerRules(where); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", where, got, want)
		}
	}
}

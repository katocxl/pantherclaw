// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"slices"
	"strings"
	"testing"
)

// Only the kinds a finished org scan read in full count misses (D114,
// HR-459): a source not read, or a note that the listing is partial,
// keeps the kinds it touches from counting.
// Covers: PN-001.3
func TestMissedKinds(t *testing.T) {
	all := []string{"mcp_configs", "org_installations", "repositories", "rulesets", "workflows"}
	for _, tc := range []struct {
		name       string
		scanned    []string
		notScanned map[string]string
		want       []string
	}{
		{"complete", all, map[string]string{}, []string{"github_app", "github_mcp_config", "github_workflow"}},
		{
			"no repositories",
			[]string{"mcp_configs", "org_installations", "workflows"},
			map[string]string{"repositories": "denied"},
			[]string{"github_app"},
		},
		{"unreadable contents", all, map[string]string{"contents": "2 repositories"}, []string{"github_app"}},
		{"findings not submitted", all, map[string]string{"findings": "some findings could not be submitted"}, nil},
		{"app unusable", nil, map[string]string{"organization": "x"}, nil},
		{
			"workflows only",
			[]string{"repositories", "workflows"},
			map[string]string{"mcp_configs": "not reported", "org_installations": "not reported"},
			[]string{"github_workflow"},
		},
	} {
		if got := missedKinds(tc.scanned, tc.notScanned); !slices.Equal(got, tc.want) {
			t.Errorf("%s: missedKinds = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestChangeValueTrimsAfterCutting: a long value cut at the limit keeps
// its text, not a trailing space that would hide it (R-474 L4).
// Covers: PN-001.3
func TestChangeValueTrimsAfterCutting(t *testing.T) {
	v := strings.Repeat("a", maxChangeValue-1) + " tail"
	if got := changeValue(v); got != strings.Repeat("a", maxChangeValue-1) {
		t.Errorf("changeValue = %q", got)
	}
	if got := changeValue(""); got != "(none)" {
		t.Errorf("empty = %q", got)
	}
	if got := changeValue("a" + string(rune(0x202e)) + "b"); got != "(not shown)" {
		t.Errorf("bidi = %q", got)
	}
}

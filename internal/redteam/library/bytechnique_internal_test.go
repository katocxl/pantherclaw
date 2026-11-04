// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package library

import (
	"slices"
	"testing"
)

// Covers: F974, HR-683
func TestByTechnique_MatchesIdsAndSubtechniques(t *testing.T) {
	saved := entries
	t.Cleanup(func() { entries = saved })
	entries = map[string]Entry{
		"RT-003": {ATTACK: []string{"T1059.001"}},
		"RT-001": {ATLAS: []string{"AML.T0051"}, ATTACK: []string{"T1059"}},
		"RT-002": {ATLAS: []string{"AML.T0051.000"}},
		"RT-004": {ATTACK: []string{"T10590"}},
	}
	for id, want := range map[string][]string{
		"T1059":         {"RT-001", "RT-003"},
		"T1059.001":     {"RT-003"},
		"AML.T0051":     {"RT-001", "RT-002"},
		"AML.T0051.000": {"RT-002"},
		"T105":          nil,
		"AML.T0052":     nil,
	} {
		if got := ByTechnique(id); !slices.Equal(got, want) {
			t.Errorf("ByTechnique(%s) = %v, want %v", id, got, want)
		}
	}
}

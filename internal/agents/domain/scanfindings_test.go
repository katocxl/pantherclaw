// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/agents/domain"
)

// TestD252_ValuesArePlainAndNamesClosed walks one value of each failure.
// Covers: F883
func TestD252_ValuesArePlainAndNamesClosed(t *testing.T) {
	for kind, attrs := range map[string]map[string]string{
		"mcp_server":    {"name": "ok", "unknown": "x", "command": strings.Repeat("a", 257)},
		"agent_project": {"path": "~/p", "manifest": "a\x00b", "frameworks": "\xff"},
		"skill":         {"name": "ok", "path": "a b"},
	} {
		kept, dropped := domain.CleanScanAttributes(kind, attrs)
		if len(kept) != 1 || dropped != len(attrs)-1 {
			t.Errorf("%s: kept %v, dropped %d", kind, kept, dropped)
		}
	}
	if kept, dropped := domain.CleanScanAttributes("unknown_kind", map[string]string{"name": "x"}); len(kept) != 0 || dropped != 1 {
		t.Errorf("a kind with no list: %v, %d", kept, dropped)
	}
	if kept, dropped := domain.CleanScanAttributes("mcp_server", map[string]string{"name": strings.Repeat("a", 256)}); len(kept) != 1 || dropped != 0 {
		t.Errorf("the longest value: %v, %d", kept, dropped)
	}
}

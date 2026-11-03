// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping_test

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/threatmap/mapping"
)

// TestHR683_TablesUseTheClosedLists: every table entry takes its surface,
// requirement, reason and tool kind from the closed lists of G0 M28 D714
// and has the shape D714 gives it. The closure test (mapset) checks the ids.
// Covers: F974, HR-683
func TestHR683_TablesUseTheClosedLists(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range mapping.Prevent {
		if !strings.HasPrefix(c.ID, "prevent.") || seen[c.ID] || c.Title == "" || !c.Surface.Valid() || !c.Requires.Valid() {
			t.Errorf("prevent control %+v", c)
		}
		seen[c.ID] = true
	}
	for _, o := range mapping.Outside {
		if o.ID == "" || !o.Reason.Valid() || !o.CoveredBy.Valid() || strings.ContainsAny(o.Note, "\r\n") {
			t.Errorf("outside entry %+v", o)
		}
	}
	for _, u := range mapping.Unaddressed {
		if u.ID == "" || !strings.Contains(u.Why, "("+u.ID+")") {
			t.Errorf("unaddressed entry %+v", u)
		}
	}
	for k, m := range mapping.Kinds {
		ids := len(m.ATLAS) + len(m.ATTACK)
		if (!strings.HasPrefix(k, "behavior.") && !strings.HasPrefix(k, "content.")) || (ids > 0) == (m.None != "") {
			t.Errorf("kind %s: %+v", k, m)
		}
	}
	for _, v := range []interface{ Valid() bool }{mapping.Surface("PHYSICAL"), mapping.Requirement("SOMETIMES"), mapping.OutsideReason("CLOUD"), mapping.ToolKind("SIEM")} {
		if v.Valid() {
			t.Errorf("%v is not on its closed list", v)
		}
	}
}

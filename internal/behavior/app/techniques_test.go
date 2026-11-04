// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"slices"
	"testing"
	"time"

	bdomain "github.com/katocxl/pantherclaw/internal/behavior/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapping"
)

// TestHR684_BehaviorSignalsCarryTheirKindsTechniques: each deviation kind's
// signal carries exactly the techniques mapping.Kinds gives it, and a kind
// that maps to none carries none (G0 M28 D718). Covers: F964, HR-684
func TestHR684_BehaviorSignalsCarryTheirKindsTechniques(t *testing.T) {
	a := bdomain.Action{ID: ids.NewV7(), Agent: ids.NewV7(), Run: ids.NewV7(), Operation: "x", At: time.Now()}
	for _, k := range allKinds {
		m, ok := mapping.Kinds["behavior."+string(k)]
		if !ok {
			t.Fatalf("%s has no mapping", k)
		}
		s := signal(ids.New[ids.Org](), bdomain.OriginReal, found{Deviation: bdomain.Deviation{Kind: k, Value: "x", Action: a, Text: "x"}})
		if !slices.Equal(s.ATLAS, m.ATLAS) || !slices.Equal(s.ATTACK, m.ATTACK) {
			t.Errorf("%s: atlas %v attack %v, want %v %v", k, s.ATLAS, s.ATTACK, m.ATLAS, m.ATTACK)
		}
		if m.None != "" && len(s.ATLAS)+len(s.ATTACK) != 0 {
			t.Errorf("%s maps to none but carries %v %v", k, s.ATLAS, s.ATTACK)
		}
		if err := s.Validate(); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	// The signal holds its own copy: changing it leaves the mapping alone.
	s := signal(ids.New[ids.Org](), bdomain.OriginReal, found{Deviation: bdomain.Deviation{Kind: bdomain.KindNewTool, Value: "x", Action: a, Text: "x"}})
	s.ATLAS[0] = "AML.T9999"
	if mapping.Kinds["behavior.NEW_TOOL"].ATLAS[0] == "AML.T9999" {
		t.Error("the signal shares the mapping's slice")
	}
}

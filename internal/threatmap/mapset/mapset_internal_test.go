// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapset

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapping"
)

func fixture() sources {
	return sources{
		prevent:     []mapping.PreventControl{{ID: "prevent.b", Techniques: []string{"T1078", "AML.T0051"}}, {ID: "prevent.a", Techniques: []string{"T1078"}}},
		kinds:       map[string]mapping.KindMapping{"behavior.NEW_TOOL": {ATTACK: []string{"T1078"}}},
		outside:     []mapping.OutsideEntry{{ID: "T1200", Reason: mapping.OutsidePhysical, CoveredBy: mapping.ToolPhysicalSecurity}},
		unaddressed: []mapping.UnaddressedEntry{{ID: "AML.T0000", Why: "x (AML.T0000)"}},
		rules:       []*rules.Rule{{ID: "pc.x.y", ATLAS: []string{"AML.T0051"}, ATTACK: []string{"T1078", "T1078"}}},
		scenarios:   map[string]library.Entry{"RT-002": {ATTACK: []string{"T1078"}}, "RT-001": {ATTACK: []string{"T1078"}}},
		campaigns:   map[string]library.CampaignEntry{"RT-140": {ATLAS: []string{"AML.T0051"}}},
	}
}

// Covers: F974, HR-683
func TestHR683_SetGathersEveryMapping(t *testing.T) {
	s, err := build(fixture())
	if err != nil {
		t.Fatal(err)
	}
	attack := s.Techniques(catalog.FrameworkATTACK)
	m := attack["T1078"]
	switch {
	case !slices.Equal(m.Prevent, []string{"prevent.a", "prevent.b"}),
		!slices.Equal(m.Rules, []string{"pc.x.y"}),
		!slices.Equal(m.Kinds, []string{"behavior.NEW_TOOL"}),
		!slices.Equal(m.Scenarios, []string{"RT-001", "RT-002"}),
		!m.Mapped():
		t.Errorf("T1078 = %+v", m)
	}
	if o := attack["T1200"]; o.Outside == nil || o.Outside.CoveredBy != mapping.ToolPhysicalSecurity || o.Mapped() {
		t.Errorf("T1200 = %+v", o)
	}
	atlas := s.Techniques(catalog.FrameworkATLAS)
	if a := atlas["AML.T0051"]; !slices.Equal(a.Campaigns, []string{"RT-140"}) || !slices.Equal(a.Rules, []string{"pc.x.y"}) {
		t.Errorf("AML.T0051 = %+v", a)
	}
	if u := atlas["AML.T0000"]; u.Unaddressed == nil || u.Mapped() {
		t.Errorf("AML.T0000 = %+v", u)
	}
	if _, ok := atlas["T1078"]; ok {
		t.Error("an ATT&CK id landed under ATLAS")
	}
	// The digest follows the content, never map order.
	again, err := build(fixture())
	if err != nil {
		t.Fatal(err)
	}
	if s.Digest() != again.Digest() || len(s.Digest()) != 64 {
		t.Errorf("digest %s / %s", s.Digest(), again.Digest())
	}
	changed := fixture()
	changed.scenarios["RT-003"] = library.Entry{ATTACK: []string{"T1059"}}
	other, err := build(changed)
	if err != nil {
		t.Fatal(err)
	}
	if other.Digest() == s.Digest() {
		t.Error("a new mapping left the digest unchanged")
	}
}

// Covers: F974, HR-683
func TestHR683_TheShippedSetLoads(t *testing.T) {
	s := Load()
	if s != Load() || len(s.Digest()) != 64 {
		t.Fatalf("Load: %p %q", s, s.Digest())
	}
	for _, f := range catalog.Frameworks() {
		if s.Techniques(f) == nil {
			t.Errorf("%s: no map", f)
		}
	}
}

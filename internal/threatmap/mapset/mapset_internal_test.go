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

// TestHR683_HubPlaybooksFollowTheirTriggerRules: a Hub playbook maps the
// techniques of the rules its trigger names (G0 M28 D714b).
// Covers: F974, HR-683
func TestHR683_HubPlaybooksFollowTheirTriggerRules(t *testing.T) {
	src := fixture()
	src.hub = HubTable{
		Rules:     []HubRule{{ID: "org.hub.r", Item: "pc.detect.r", ATTACK: []string{"T1059"}}},
		Playbooks: []HubPlaybook{{Name: "pc.playbook.p", Rules: []string{"pc.x.y", "org.hub.r", "pc.nope.gone"}}},
	}
	s, err := build(src)
	if err != nil {
		t.Fatal(err)
	}
	attack := s.Techniques(catalog.FrameworkATTACK)
	if m := attack["T1059"]; !slices.Equal(m.HubRules, []string{"org.hub.r"}) || !slices.Equal(m.HubPlaybooks, []string{"pc.playbook.p"}) {
		t.Errorf("T1059 = %+v", m)
	}
	if m := attack["T1078"]; !slices.Equal(m.HubPlaybooks, []string{"pc.playbook.p"}) {
		t.Errorf("T1078 = %+v: the playbook follows pc.x.y", m)
	}
	if !slices.Contains(s.Unknown(), "pc.playbook.p: trigger rule pc.nope.gone") {
		t.Errorf("unknown = %v", s.Unknown())
	}
}

// TestHR683_UnknownIdsAreNamed: an id of neither framework is skipped and
// named with its source (G0 M28 D714a, D714c L4).
// Covers: F974, HR-683
func TestHR683_UnknownIdsAreNamed(t *testing.T) {
	src := fixture()
	src.scenarios["RT-009"] = library.Entry{ATTACK: []string{"X1"}}
	src.prevent = append(src.prevent, mapping.PreventControl{ID: "prevent.c", Techniques: []string{"ASI01"}})
	s, err := build(src)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Unknown(); !slices.Equal(got, []string{"RT-009: X1", "prevent.c: ASI01"}) {
		t.Errorf("unknown = %v", got)
	}
	s.Unknown()[0] = "changed"
	if s.Unknown()[0] == "changed" {
		t.Error("Unknown shares its slice")
	}
}

// TestHR683_TechniquesAreCopies: no caller can change the set (G0 M28
// D714c L5).
// Covers: F974, HR-683
func TestHR683_TechniquesAreCopies(t *testing.T) {
	s, err := build(fixture())
	if err != nil {
		t.Fatal(err)
	}
	a := s.Techniques(catalog.FrameworkATTACK)
	a["T1078"].Prevent[0] = "changed"
	a["T1200"].Outside.Note = "changed"
	delete(a, "T1078")
	b := s.Techniques(catalog.FrameworkATTACK)
	if b["T1078"].Prevent[0] != "prevent.a" || b["T1200"].Outside.Note != "" {
		t.Error("Techniques shares its contents")
	}
}

// TestHR683_DigestCoversTheWholeDocument: every field of the mapping
// document changes the digest, not only the technique index (G0 M28 D714c
// M2).
// Covers: F974, HR-683
func TestHR683_DigestCoversTheWholeDocument(t *testing.T) {
	base, err := build(fixture())
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*sources){
		"prevent title":    func(s *sources) { s.prevent[0].Title = "Changed" },
		"prevent HR":       func(s *sources) { s.prevent[0].HR = []string{"HR-001"} },
		"prevent reason":   func(s *sources) { s.prevent[0].ReasonCodes = []string{"NO_GRANT"} },
		"prevent requires": func(s *sources) { s.prevent[0].Requires = mapping.RequiresAlways },
		"prevent why":      func(s *sources) { s.prevent[0].Why = map[string]string{"T1078": "x (T1078)"} },
		"kind none":        func(s *sources) { s.kinds["content.pii_email"] = mapping.KindMapping{None: "x"} },
		"outside note":     func(s *sources) { s.outside[0].Note = "x" },
		"outside tool":     func(s *sources) { s.outside[0].CoveredBy = mapping.ToolEDR },
		"unaddressed why":  func(s *sources) { s.unaddressed[0].Why = "y (AML.T0000)" },
		"rule none":        func(s *sources) { s.rules = append(s.rules, &rules.Rule{ID: "pc.a.b", TechniquesNone: "x"}) },
		"scenario none":    func(s *sources) { s.scenarios["RT-020"] = library.Entry{TechniquesNone: "x"} },
		"scenario why": func(s *sources) {
			s.scenarios["RT-001"] = library.Entry{ATTACK: []string{"T1078"}, TechniqueWhy: map[string]string{"T1078": "x (T1078)"}}
		},
		"campaign none": func(s *sources) { s.campaigns["RT-141"] = library.CampaignEntry{TechniquesNone: "x"} },
		"hub rule":      func(s *sources) { s.hub.Rules = []HubRule{{ID: "org.hub.x", Item: "pc.detect.x"}} },
		"hub playbook":  func(s *sources) { s.hub.Playbooks = []HubPlaybook{{Name: "pc.playbook.x", Rules: []string{}}} },
	} {
		src := fixture()
		edit(&src)
		s, err := build(src)
		if err != nil {
			t.Fatal(err)
		}
		if s.Digest() == base.Digest() {
			t.Errorf("%s: the digest did not change", name)
		}
	}
}

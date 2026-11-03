// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ocsf_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
	"github.com/katocxl/pantherclaw/internal/siem/ocsf"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
)

// TestT306_OCSFAttacksCarryATTACKWithNamesTacticsAndVersions: an alert's
// ATT&CK techniques reach the export beside its ATLAS ones, one object per
// tactic, a sub-technique under its parent, with names and tactics from the
// pinned catalog and each framework's version; an id the catalog lacks
// keeps its uid (G0 M28 D718). Covers: F965, HR-684, T-306
func TestT306_OCSFAttacksCarryATTACKWithNamesTacticsAndVersions(t *testing.T) {
	s := techSignal()
	s.ATLAS, s.ATTACK = []string{"AML.T0053"}, []string{"T1552.001"}
	e, err := feed.Normalize(reflexdomain.KindAlert, "system", "reflex", techAt, alerts.EntryBody(s, ids.NewV7(), alerts.StateOpen))
	if err != nil {
		t.Fatal(err)
	}
	if e.Attrs[ocsf.AttrATTACK] != "T1552.001" {
		t.Fatalf("attack attr %q", e.Attrs[ocsf.AttrATTACK])
	}
	r := ocsf.Map(e, "test")
	got := attackUIDs(r.FindingInfo)
	want := []string{"AML.T0053@AML.TA0005", "AML.T0053@AML.TA0012", "AML.T0053@AML.TA0015", "T1552/T1552.001@TA0006"}
	if !slices.Equal(got, want) {
		t.Fatalf("attacks %v, want %v", got, want)
	}
	atlas, attack := catalog.Load(catalog.FrameworkATLAS), catalog.Load(catalog.FrameworkATTACK)
	last := r.FindingInfo.Attacks[len(r.FindingInfo.Attacks)-1]
	if last.Version != attack.Version || last.Technique.Name != "Unsecured Credentials" ||
		last.SubTechnique.Name != "Credentials In Files" || last.Tactic.Name != "Credential Access" {
		t.Errorf("ATT&CK attack %+v %+v %+v %q", last.Tactic, last.Technique, last.SubTechnique, last.Version)
	}
	first := r.FindingInfo.Attacks[0]
	if first.Version != "ATLAS "+atlas.Version || first.Technique.Name != "AI Agent Tool Invocation" || first.SubTechnique != nil {
		t.Errorf("ATLAS attack %+v %+v %q", first.Technique, first.SubTechnique, first.Version)
	}
	// The attack attribute is mapped, so it does not repeat in unmapped.
	if r.Unmapped != nil && r.Unmapped.Attrs[ocsf.AttrATTACK] != "" {
		t.Errorf("attack left in unmapped: %v", r.Unmapped.Attrs)
	}

	// An id the pinned catalog does not know keeps its uid alone.
	e.ATLAS, e.ATTACK = nil, []string{"T9999"}
	r = ocsf.Map(e, "test")
	if got := attackUIDs(r.FindingInfo); !slices.Equal(got, []string{"T9999"}) || r.FindingInfo.Attacks[0].Version != attack.Version {
		t.Errorf("unknown id: %v %+v", got, r.FindingInfo.Attacks)
	}
}

var techAt = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func techSignal() reflexdomain.Signal {
	return reflexdomain.Signal{
		Source: "detection", RuleID: "pc.identity.key_new_network", RuleVersion: "1", Title: "t",
		Severity: reflexdomain.SeverityHigh, Attention: reflexdomain.AttentionAlert, Basis: reflexdomain.BasisRuleMatch,
		Subjects: []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: "0192f0a0-0000-7000-8000-0000000000bb"}},
		ATLAS:    []string{"AML.T0051.000", "AML.T0024"}, OWASP: []string{"ASI03"},
	}
}

// attackUIDs names each attack object "technique[/sub]@tactic".
func attackUIDs(f *ocsf.FindingInfo) []string {
	var out []string
	for _, a := range f.Attacks {
		s := a.Technique.UID
		if a.SubTechnique != nil {
			s += "/" + a.SubTechnique.UID
		}
		if a.Tactic != nil {
			s += "@" + a.Tactic.UID
		}
		out = append(out, s)
	}
	return out
}

// TestHR684_AlertLedgerBodyCarriesTechniques: the alert's ledger body keeps
// the rule's ATLAS techniques and OWASP risks, and the feed passes them on
// sorted (G0 M28 D718). Covers: F964, HR-684
func TestHR684_AlertLedgerBodyCarriesTechniques(t *testing.T) {
	body := alerts.EntryBody(techSignal(), ids.NewV7(), alerts.StateOpen)
	e, err := feed.Normalize(reflexdomain.KindAlert, "system", "reflex", techAt, body)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Attrs[ocsf.AttrATLAS]; got != "AML.T0024,AML.T0051.000" {
		t.Errorf("atlas attr %q", got)
	}
	if got := e.Attrs[ocsf.AttrOWASP]; got != "ASI03" {
		t.Errorf("owasp attr %q", got)
	}
	// A signal with no mapping writes no empty keys.
	s := techSignal()
	s.ATLAS, s.OWASP = nil, nil
	e, err = feed.Normalize(reflexdomain.KindAlert, "system", "reflex", techAt, alerts.EntryBody(s, ids.NewV7(), alerts.StateOpen))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Attrs[ocsf.AttrATLAS]; ok {
		t.Errorf("empty atlas attr: %v", e.Attrs)
	}
}

// TestT306_ExportedOCSFAlertCarriesAttacks: an alert raised by a mapped
// rule reaches the SIEM export with its techniques in
// finding_info.attacks and its risks in finding_info.types; the ledger
// body used to drop them (G0 M28 D718). Covers: F964, F965, HR-684, T-306
func TestT306_ExportedOCSFAlertCarriesAttacks(t *testing.T) {
	body := alerts.EntryBody(techSignal(), ids.NewV7(), alerts.StateOpen)
	e, err := feed.Normalize(reflexdomain.KindAlert, "system", "reflex", techAt, body)
	if err != nil {
		t.Fatal(err)
	}
	r := ocsf.Map(e, "test")
	if r.FindingInfo == nil {
		t.Fatalf("no finding_info: %+v", r)
	}
	if got := attackUIDs(r.FindingInfo); !slices.Equal(got, []string{"AML.T0024@AML.TA0010", "AML.T0051/AML.T0051.000@AML.TA0005"}) {
		t.Errorf("attacks %v", got)
	}
	if !slices.Equal(r.FindingInfo.Types, []string{"ASI03"}) {
		t.Errorf("types %v", r.FindingInfo.Types)
	}
	enc, err := ocsf.Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(string(enc), `"attacks"`, `"AML.T0051.000"`) {
		t.Errorf("encoded record lacks attacks: %s", enc)
	}
}

// TestT306_ExportedOCSFIncidentCarriesAttacks: an incident's ledger entry
// carries the union of its alerts' techniques and its OCSF incident
// finding lists them (G0 M28 D718). Covers: F964, F965, HR-684, T-306
func TestT306_ExportedOCSFIncidentCarriesAttacks(t *testing.T) {
	body, err := reflexapp.IncidentEntryBody(dbq.PcIncident{
		ID: ids.NewV7(), State: "OPEN", Severity: "HIGH", Atlas: []string{"AML.T0024", "AML.T0051"},
	}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	e, err := feed.Normalize(reflexdomain.KindIncident, "system", "reflex", techAt, body)
	if err != nil {
		t.Fatal(err)
	}
	r := ocsf.Map(e, "test")
	if len(r.FindingList) != 1 {
		t.Fatalf("finding list %+v", r.FindingList)
	}
	if got := attackUIDs(&r.FindingList[0]); !slices.Equal(got, []string{"AML.T0024@AML.TA0010", "AML.T0051@AML.TA0005"}) {
		t.Errorf("attacks %v", got)
	}
	// An incident with no techniques writes no technique keys.
	body, err = reflexapp.IncidentEntryBody(dbq.PcIncident{ID: ids.NewV7(), State: "OPEN", Severity: "HIGH"}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if containsAll(string(body), "atlas") || containsAll(string(body), "attack") {
		t.Errorf("empty technique keys in %s", body)
	}
}

// TestT306_IncidentWith64TechniquesExports64: an incident's full union
// reaches the SIEM export even where the feed attribute is cut to 512
// bytes (G0 M28 D718b, review M1). Covers: F965, HR-684, T-306
func TestT306_IncidentWith64TechniquesExports64(t *testing.T) {
	var atlas, attack []string
	for _, x := range catalog.Load(catalog.FrameworkATLAS).Techniques {
		if x.Parent != "" && len(atlas) < 64 {
			atlas = append(atlas, x.ID)
		}
	}
	for _, x := range catalog.Load(catalog.FrameworkATTACK).Techniques {
		if x.Parent != "" && len(attack) < 64 {
			attack = append(attack, x.ID)
		}
	}
	if len(atlas) != 64 || len(attack) != 64 {
		t.Fatalf("catalog fixture: %d ATLAS, %d ATT&CK sub-techniques", len(atlas), len(attack))
	}
	body, err := reflexapp.IncidentEntryBody(dbq.PcIncident{
		ID: ids.NewV7(), State: "OPEN", Severity: "HIGH", Atlas: atlas, Attack: attack,
	}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	e, err := feed.Normalize(reflexdomain.KindIncident, "system", "reflex", techAt, body)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Split(e.Attrs[ocsf.AttrATLAS], ",")); n >= 64 {
		t.Fatalf("fixture does not exercise the cut: %d ids in the attribute", n)
	}
	r := ocsf.Map(e, "test")
	subs := map[string]bool{}
	for _, a := range r.FindingList[0].Attacks {
		if a.SubTechnique == nil {
			t.Fatalf("attack without its sub-technique: %+v", a)
		}
		subs[a.SubTechnique.UID] = true
	}
	for _, id := range slices.Concat(atlas, attack) {
		if !subs[id] {
			t.Errorf("%s missing from the export", id)
		}
	}
	if len(subs) != 128 {
		t.Errorf("exported %d techniques, want 128 (64 per framework)", len(subs))
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

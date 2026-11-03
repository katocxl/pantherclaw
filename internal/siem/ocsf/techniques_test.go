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
)

var techAt = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func techSignal() reflexdomain.Signal {
	return reflexdomain.Signal{
		Source: "detection", RuleID: "pc.identity.key_new_network", RuleVersion: "1", Title: "t",
		Severity: reflexdomain.SeverityHigh, Attention: reflexdomain.AttentionAlert, Basis: reflexdomain.BasisRuleMatch,
		Subjects: []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: "0192f0a0-0000-7000-8000-0000000000bb"}},
		ATLAS:    []string{"AML.T0051.000", "AML.T0024"}, OWASP: []string{"ASI03"},
	}
}

func attackUIDs(f *ocsf.FindingInfo) []string {
	var out []string
	for _, a := range f.Attacks {
		out = append(out, a.Technique.UID)
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
	if got := attackUIDs(r.FindingInfo); !slices.Equal(got, []string{"AML.T0024", "AML.T0051.000"}) {
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
	if got := attackUIDs(&r.FindingList[0]); !slices.Equal(got, []string{"AML.T0024", "AML.T0051"}) {
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

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

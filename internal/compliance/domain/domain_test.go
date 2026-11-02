// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"encoding/json/v2"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/compliance/domain"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
)

func allReadable(realCount, simulated int64) domain.Inputs {
	var in domain.Inputs
	for _, s := range slices.Concat(domain.RecordSources(), domain.TestSources()) {
		c := domain.SourceCount{Source: s, Readable: true}
		if slices.Contains(domain.RecordSources(), s) {
			c.Real, c.Simulated = realCount, simulated
		}
		in.Sources = append(in.Sources, c)
	}
	return in
}

func control(t *testing.T, f domain.Framework, in domain.Inputs, id string) domain.ControlResult {
	t.Helper()
	got, err := domain.Evaluate(f, in)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(got, func(c domain.ControlResult) bool { return c.ID == id })
	if i < 0 {
		t.Fatalf("%s has no control %s", f, id)
	}
	return got[i]
}

func reasons(r domain.ControlResult) []string {
	out := []string{}
	for _, g := range r.Gaps {
		out = append(out, g.Reason)
	}
	return out
}

// TestD300_FiveFrameworksExactly: the closed list of D300.
// Covers: F890
func TestD300_FiveFrameworksExactly(t *testing.T) {
	want := []domain.Framework{"OWASP_ASI", "NIST_AI_RMF", "EU_AI_ACT_DEPLOYER", "ISO_42001", "SOC2"}
	if got := domain.Frameworks(); !slices.Equal(got, want) {
		t.Fatalf("frameworks: %v", got)
	}
	for _, f := range want {
		if !f.Known() || f.Title() == "" || len(domain.Controls(f)) == 0 || len(domain.CatalogDigest(f)) != 64 {
			t.Errorf("%s: incomplete", f)
		}
	}
	if domain.Framework("DORA").Known() || domain.Controls("DORA") != nil {
		t.Error("an unlisted framework is known")
	}
}

// TestD300_OWASPTableIsTheClosedRiskList: each risk of the detection rules'
// closed list is one control, in order, and every test tag names one of them.
// Covers: F890
func TestD300_OWASPTableIsTheClosedRiskList(t *testing.T) {
	var ids []string
	for _, c := range domain.Controls(domain.OWASPASI) {
		ids = append(ids, c.ID)
		if !rules.KnownOWASP(c.ID) {
			t.Errorf("%s is not a listed risk", c.ID)
		}
	}
	if len(ids) != 10 || !slices.IsSorted(ids) || slices.Contains(ids, "") {
		t.Fatalf("controls: %v", ids)
	}
	for _, f := range domain.Frameworks() {
		for _, c := range domain.Controls(f) {
			for _, tag := range c.Tests {
				if !rules.KnownOWASP(tag) {
					t.Errorf("%s %s: test tag %q", f, c.ID, tag)
				}
			}
		}
	}
}

// TestD300_ControlsAreWellFormed: unique ids, and each control reads exactly
// one of records and tests, a stated field, or a named reason it cannot.
// Covers: F890
func TestD300_ControlsAreWellFormed(t *testing.T) {
	for _, f := range domain.Frameworks() {
		seen := map[string]bool{}
		for _, c := range domain.Controls(f) {
			if c.ID == "" || c.Title == "" || seen[c.ID] {
				t.Errorf("%s: control %q", f, c.ID)
			}
			seen[c.ID] = true
			kinds := 0
			if len(c.Records) > 0 || len(c.Tests) > 0 {
				kinds++
			}
			if c.Stated != "" {
				kinds++
			}
			if c.Outside != "" {
				kinds++
			}
			if kinds != 1 {
				t.Errorf("%s %s reads %d kinds of thing", f, c.ID, kinds)
			}
			for _, s := range c.Records {
				if !slices.Contains(domain.RecordSources(), s) {
					t.Errorf("%s %s: %q is not a production record", f, c.ID, s)
				}
			}
		}
	}
}

// bannedWords would read as a claim the product never makes.
var bannedWords = regexp.MustCompile(`(?i)\b(compliant|certified|certifies|score|percent|passed|safe)\b`)

// TestHR600_NoReportSaysCompliant: nothing a report is built from, or derives,
// can say a customer meets a framework, and a report has no score: the only
// numbers are counts of records.
// Covers: F891
func TestHR600_NoReportSaysCompliant(t *testing.T) {
	for _, f := range domain.Frameworks() {
		for _, in := range []domain.Inputs{{}, allReadable(0, 0), allReadable(5, 2)} {
			got, err := domain.Evaluate(f, in)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(domain.Report{Framework: f, Controls: got, Inputs: in})
			if err != nil {
				t.Fatal(err)
			}
			if m := bannedWords.FindString(string(raw)); m != "" {
				t.Errorf("%s: a report says %q", f, m)
			}
		}
		if m := bannedWords.FindString(f.Title()); m != "" {
			t.Errorf("%s title: %q", f, m)
		}
	}
	report := reflectFields(domain.Report{})
	for _, name := range report {
		if strings.Contains(strings.ToLower(name), "score") || strings.Contains(strings.ToLower(name), "percent") {
			t.Errorf("a report has a field %s", name)
		}
	}
}

func reflectFields(v any) []string {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return slices.Collect(maps.Keys(m))
}

// TestHR601_StatedIsNeverEvidence: a stated field yields STATED however many
// agents state it, and no quantity of records turns it into EVIDENCED. An AI
// Act role or risk class is a person's word (D302, migration 00273).
// Covers: F891
func TestHR601_StatedIsNeverEvidence(t *testing.T) {
	in := allReadable(1000, 0)
	in.Stated = []domain.StatedCount{
		{Field: domain.FieldAIActRole, Readable: true, Stated: 50},
		{Field: domain.FieldAIActRisk, Readable: true, Stated: 40, Unset: 10},
	}
	role := control(t, domain.EUAIActDeployer, in, "ART-3-ROLE")
	if role.State != domain.Stated || !slices.Equal(role.Evidence, []domain.Source{domain.SourceStated}) {
		t.Errorf("role: %+v", role)
	}
	risk := control(t, domain.EUAIActDeployer, in, "ART-6-CLASS")
	if risk.State != domain.Stated || !slices.Equal(reasons(risk), []string{domain.ReasonNotStated}) {
		t.Errorf("risk with unset agents: %+v", risk)
	}
	for _, c := range domain.Controls(domain.EUAIActDeployer) {
		if c.Stated != "" && (len(c.Records) > 0 || len(c.Tests) > 0) {
			t.Errorf("%s mixes a statement with evidence", c.ID)
		}
	}
	in.Stated = nil
	if got := control(t, domain.EUAIActDeployer, in, "ART-3-ROLE"); got.State != domain.Gap {
		t.Errorf("unreadable statement: %s", got.State)
	}
	in.Stated = []domain.StatedCount{{Field: domain.FieldAIActRole, Readable: true, Unset: 3}}
	if got := control(t, domain.EUAIActDeployer, in, "ART-3-ROLE"); got.State != domain.Gap {
		t.Errorf("nothing stated: %s", got.State)
	}
}

// TestHR602_SimulatedOnlyIsNeverEvidenced: simulated activity is split and
// labeled, and alone it never makes a control EVIDENCED (F630).
// Covers: F891
func TestHR602_SimulatedOnlyIsNeverEvidenced(t *testing.T) {
	got := control(t, domain.SOC2, allReadable(0, 9), "CC7.2")
	if got.State != domain.Partial || !got.SimulatedOnly || !slices.Equal(reasons(got), []string{domain.ReasonSimulatedOnly}) {
		t.Fatalf("simulated receipts: %+v", got)
	}
	if s := domain.SplitOf(allReadable(3, 9)); s.Real != 12 || s.Simulated != 36 {
		t.Errorf("split: %+v", s)
	}
	in := allReadable(0, 0)
	in.Tests = []domain.TestCount{{Tag: "ASI05", Source: domain.SourceRange, Held: 4}}
	asi05 := control(t, domain.OWASPASI, in, "ASI05")
	if asi05.State != domain.Partial || !asi05.SimulatedOnly || !slices.Equal(reasons(asi05), []string{domain.ReasonSimulatedOnly}) {
		t.Fatalf("tests alone: %+v", asi05)
	}
}

// TestHR603_UnreadableIsAGapNeverZero: what the reader may not read is a gap
// that says so, not a count of nothing (D312).
// Covers: F891
func TestHR603_UnreadableIsAGapNeverZero(t *testing.T) {
	got := control(t, domain.SOC2, domain.Inputs{}, "CC7.2")
	if got.State != domain.Gap || !slices.Equal(reasons(got), []string{domain.ReasonOutsidePermission}) {
		t.Fatalf("no sources: %+v", got)
	}
	in := allReadable(3, 0)
	in.Sources[slices.IndexFunc(in.Sources, func(c domain.SourceCount) bool { return c.Source == domain.SourceApprovals })].Readable = false
	in.Tests = []domain.TestCount{{Tag: "ASI02", Source: domain.SourceRange, Held: 2}}
	asi02 := control(t, domain.OWASPASI, in, "ASI02")
	if asi02.State != domain.Partial || !slices.Equal(reasons(asi02), []string{domain.ReasonOutsidePermission}) {
		t.Fatalf("one source unreadable: %+v", asi02)
	}
}

// TestD302_States walks a control from a gap to evidenced.
// Covers: F891
func TestD302_States(t *testing.T) {
	cases := []struct {
		name  string
		in    domain.Inputs
		state domain.State
		gaps  []string
	}{
		{"nothing", allReadable(0, 0), domain.Gap, []string{domain.ReasonNoRecords, domain.ReasonNotExercised}},
		{"records only", allReadable(2, 0), domain.Partial, []string{domain.ReasonNotExercised}},
		{"records and a held test", withTests(allReadable(2, 0), domain.TestCount{Tag: "ASI01", Source: domain.SourceRange, Held: 1}), domain.Evidenced, []string{}},
		{"a campaign is enough", withTests(allReadable(2, 0), domain.TestCount{Tag: "ASI01", Source: domain.SourceCampaign, Held: 1}), domain.Evidenced, []string{}},
		{"a failure stays", withTests(allReadable(2, 0), domain.TestCount{Tag: "ASI01", Source: domain.SourceRange, Held: 3, Failed: 1}), domain.Partial, []string{domain.ReasonTestFailed}},
		{"only a failure", withTests(allReadable(0, 0), domain.TestCount{Tag: "ASI01", Source: domain.SourceRange, Failed: 1}), domain.Gap, []string{domain.ReasonNoRecords, domain.ReasonTestFailed}},
		{"a report is not proof", withTests(allReadable(2, 0), domain.TestCount{Tag: "ASI01", Source: domain.SourceCampaign, Reported: 1}), domain.Partial, []string{domain.ReasonReportedOnly}},
		{"not exercised is no pass", withTests(allReadable(2, 0), domain.TestCount{Tag: "ASI01", Source: domain.SourceCampaign, NotExercised: 2}), domain.Partial, []string{domain.ReasonNotExercised}},
		{"another tag says nothing", withTests(allReadable(2, 0), domain.TestCount{Tag: "ASI09", Source: domain.SourceRange, Held: 9}), domain.Partial, []string{domain.ReasonNotExercised}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := control(t, domain.OWASPASI, c.in, "ASI01")
			if got.State != c.state || !slices.Equal(reasons(got), c.gaps) {
				t.Errorf("%s %v", got.State, reasons(got))
			}
		})
	}
}

func withTests(in domain.Inputs, ts ...domain.TestCount) domain.Inputs {
	in.Tests = ts
	return in
}

// TestD304_ASI05AndASI06ReadAsGaps: no production record maps them, so
// however much the org did they stay gaps until a tagged test exercised them.
// Covers: F890, F898
func TestD304_ASI05AndASI06ReadAsGaps(t *testing.T) {
	for _, id := range []string{"ASI05", "ASI06"} {
		got := control(t, domain.OWASPASI, allReadable(1000, 1000), id)
		if got.State != domain.Gap || !slices.Equal(reasons(got), []string{domain.ReasonNotExercised}) {
			t.Errorf("%s: %+v", id, got)
		}
	}
}

// TestD300_OutsideRecordsIsListedAsAGap: an obligation no record reaches is
// on the report, as a gap, whatever else the org did.
// Covers: F890
func TestD300_OutsideRecordsIsListedAsAGap(t *testing.T) {
	in := allReadable(9, 0)
	in.Tests = []domain.TestCount{{Tag: "ASI01", Source: domain.SourceRange, Held: 1}}
	got := control(t, domain.EUAIActDeployer, in, "ART-27")
	if got.State != domain.Gap || !slices.Equal(reasons(got), []string{domain.ReasonOutsideRecords}) {
		t.Fatalf("%+v", got)
	}
}

func TestEvaluateRefusesAnUnknownFramework(t *testing.T) {
	if _, err := domain.Evaluate("DORA", domain.Inputs{}); err == nil {
		t.Fatal("DORA evaluated")
	}
}

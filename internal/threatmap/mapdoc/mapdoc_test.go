// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapdoc_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	rtdomain "github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapdoc"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapset"
)

var update = flag.Bool("update", false, "rewrite docs/security/MITRE_MAPPING.md")

const (
	docPath      = "../../../docs/security/MITRE_MAPPING.md"
	scenarioDir  = "../../../redteam/scenarios"
	theStatement = "This map shows the PantherClaw controls mapped to each technique and the evidence for them. " +
		"A mapped control covers the technique, not every way of carrying it out. " +
		"Techniques outside PantherClaw need other tools. It is not a score or a guarantee."
)

// threats reads the abuse cases each library scenario's file cites, keeping
// only scenarios in the library (G0 M28: techniques by abuse case).
func threats(t *testing.T) map[string][]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(scenarioDir, "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no scenario files under %s", scenarioDir)
	}
	lib := library.All()
	out := map[string][]string{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s, err := rtdomain.Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if _, ok := lib[s.ID]; ok {
			out[s.ID] = s.Threats
		}
	}
	return out
}

// TestMITREMappingDocIsCurrent: the checked-in MITRE_MAPPING.md is what
// the code declares, so the public mapping never drifts from it. Run
// `task docs:mitre` (this test with -update) after changing a mapping or a
// scenario's threats.
// Covers: F974
func TestMITREMappingDocIsCurrent(t *testing.T) {
	want := mapdoc.Render(mapset.Load(), threats(t))
	if *update {
		if err := os.WriteFile(docPath, want, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("docs/security/MITRE_MAPPING.md is stale: task docs:mitre")
	}
}

// TestStatementIsTheThreatMapStatement: the document carries the threat
// map's fixed statement word for word (HR-681).
// Covers: F974, HR-681
func TestStatementIsTheThreatMapStatement(t *testing.T) {
	if mapdoc.Statement != theStatement {
		t.Fatalf("Statement = %q, want the fixed threat-map statement", mapdoc.Statement)
	}
}

// TestRenderListsEveryMatrixTechnique: each matrix cell of both frameworks
// appears, and the rendering is stable.
// Covers: F974
func TestRenderListsEveryMatrixTechnique(t *testing.T) {
	s, th := mapset.Load(), threats(t)
	doc := mapdoc.Render(s, th)
	if !bytes.Equal(doc, mapdoc.Render(s, th)) {
		t.Fatal("Render is not stable")
	}
	text := string(doc)
	for _, f := range catalog.Frameworks() {
		for _, tech := range catalog.Load(f).Matrix() {
			if !strings.Contains(text, "| ["+tech.ID+"](") {
				t.Errorf("%s %s is missing", f, tech.ID)
			}
		}
	}
	if strings.Contains(text, "| Not placed |") {
		t.Error("a technique has no place; the closure test should have failed")
	}
	if !strings.Contains(text, "> "+theStatement+"\n") {
		t.Error("the statement is missing")
	}
}

// banned are the words no threat-map text may use (G0 M28 wording rule),
// matched case-insensitively on word boundaries, and a digit followed by %.
var banned = regexp.MustCompile(`(?i)\b(protected|protects|protection|compliant|certified|secure|safe|score|percent|blocked|clean|none found)\b|[0-9]\s*%`)

// TestHR681_MappingDocUsesNoBannedWord: apart from the fixed statement and
// MITRE's own technique and tactic names, the page uses no banned word and
// no percentage.
// Covers: HR-681, F974
func TestHR681_MappingDocUsesNoBannedWord(t *testing.T) {
	text := string(mapdoc.Render(mapset.Load(), threats(t)))
	text = strings.ReplaceAll(text, theStatement, "")
	var names []string
	for _, f := range catalog.Frameworks() {
		c := catalog.Load(f)
		for _, ta := range c.Tactics {
			names = append(names, ta.Name)
		}
		for _, tech := range c.Techniques {
			names = append(names, tech.Name)
		}
	}
	// Longest first, so a name inside a longer one is not cut out first.
	slices.SortFunc(names, func(a, b string) int { return len(b) - len(a) })
	for _, n := range names {
		if n != "" {
			text = strings.ReplaceAll(text, n, "")
		}
	}
	for _, m := range banned.FindAllString(text, -1) {
		t.Errorf("banned wording %q in MITRE_MAPPING.md", m)
	}
}

// TestMappedParentNamesItsUncoveredSubtechniques: a technique mapped
// through some sub-techniques, with others that nothing maps to and that
// have no other place, is "Mapped (partly)" and names each of those as not
// covered; a technique with none such is "Mapped" (D1221a R1).
// Covers: F974
func TestMappedParentNamesItsUncoveredSubtechniques(t *testing.T) {
	s := mapset.Load()
	text := string(mapdoc.Render(s, threats(t)))
	empty := func(m mapset.TechniqueMappings) bool {
		return m.Outside == nil && m.Unaddressed == nil && len(m.Prevent)+len(m.Rules)+len(m.Kinds)+
			len(m.Scenarios)+len(m.Campaigns)+len(m.HubRules)+len(m.HubPlaybooks) == 0
	}
	partly := 0
	for _, f := range catalog.Frameworks() {
		c, m := catalog.Load(f), s.Techniques(f)
		for _, tech := range c.Matrix() {
			var rows []string
			for line := range strings.Lines(text) {
				if strings.HasPrefix(line, "| ["+tech.ID+"](") {
					rows = append(rows, line)
				}
			}
			if len(rows) == 0 || (!strings.Contains(rows[0], "| Mapped |") && !strings.Contains(rows[0], "| Mapped (partly) |")) {
				continue
			}
			var uncovered []string
			for _, sub := range c.Subtechniques(tech.ID) {
				if empty(m[sub.ID]) {
					uncovered = append(uncovered, sub.ID)
				}
			}
			for _, row := range rows {
				if len(uncovered) == 0 {
					if !strings.Contains(row, "| Mapped |") {
						t.Errorf("%s has every sub-technique placed but is not plain Mapped: %s", tech.ID, row)
					}
					continue
				}
				if !strings.Contains(row, "| Mapped (partly) |") {
					t.Errorf("%s leaves %v uncovered but is not Mapped (partly): %s", tech.ID, uncovered, row)
				}
				for _, id := range uncovered {
					if !strings.Contains(row, id+" not covered") {
						t.Errorf("%s does not name %s as not covered: %s", tech.ID, id, row)
					}
				}
			}
			if len(uncovered) > 0 {
				partly++
			}
		}
	}
	if partly == 0 {
		t.Error("no technique is Mapped (partly); the case is not exercised")
	}
	for line := range strings.Lines(text) {
		if !strings.HasPrefix(line, "| [T1696](") {
			continue
		}
		if !strings.Contains(line, "| Mapped (partly) |") || !strings.Contains(line, "T1696.002 not covered") {
			t.Errorf("T1696 does not name T1696.002 as not covered: %s", line)
		}
	}
}

// TestAbuseCaseRows: a row's ids are the union of its library scenarios'
// entries; a scenario outside the library or with no technique adds
// nothing, and an abuse case with no id gets no row.
// Covers: F974
func TestAbuseCaseRows(t *testing.T) {
	var mapped, none string
	for id, e := range library.All() {
		switch {
		case len(e.ATLAS)+len(e.ATTACK) > 0 && (mapped == "" || id < mapped):
			mapped = id
		case e.TechniquesNone != "" && (none == "" || id < none):
			none = id
		}
	}
	if mapped == "" {
		t.Fatal("no library scenario maps a technique")
	}
	th := map[string][]string{
		mapped:     {"T-998"},
		"RT-99999": {"T-997"}, // not in the library
	}
	if none != "" {
		th[none] = []string{"T-996"}
	}
	text := string(mapdoc.Render(mapset.Load(), th))
	_, section, ok := strings.Cut(text, "## Techniques by abuse case")
	if !ok {
		t.Fatal("no abuse-case section")
	}
	e, _ := library.Lookup(mapped)
	row := "| T-998 | "
	if !strings.Contains(section, row) {
		t.Fatalf("no row for T-998:\n%s", section)
	}
	for _, id := range append(append([]string{}, e.ATLAS...), e.ATTACK...) {
		if !strings.Contains(section, id) {
			t.Errorf("row T-998 lacks %s", id)
		}
	}
	for _, absent := range []string{"T-997", "T-996"} {
		if strings.Contains(section, "| "+absent+" |") {
			t.Errorf("%s has a row", absent)
		}
	}
}

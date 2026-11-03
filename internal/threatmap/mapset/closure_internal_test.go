// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapset

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	behavior "github.com/katocxl/pantherclaw/internal/behavior/domain"
	contentsignals "github.com/katocxl/pantherclaw/internal/contentsignals/domain"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapping"
)

// root is the repository root, from this package's directory.
const root = "../../.."

// facts is what the closure checks read besides the sources: the hardening
// rules that exist and the reason codes the decision code can return.
type facts struct {
	hr      map[string]bool
	reasons map[string]bool
}

// bannedWord is the D717 list: words a threat-map line never uses.
var bannedWord = regexp.MustCompile(`(?i)\b(protected|protects|protection|compliant|certified|secure|safe|score|percent|blocked|clean)\b|none found`)

// expectedKinds are the behavior deviation kinds and the content signal
// kinds but scan_incomplete, an owned failure (D714).
var expectedKinds = []string{
	"behavior." + string(behavior.KindNewTool), "behavior." + string(behavior.KindNewDestination),
	"behavior." + string(behavior.KindUnusualHour), "behavior." + string(behavior.KindNewSequence),
	"behavior." + string(behavior.KindVolumeSpike), "behavior." + string(behavior.KindSpendSpike),
	"content." + contentsignals.KindInjectionPhrase, "content." + contentsignals.KindSecretFormat,
	"content." + contentsignals.KindHighEntropy, "content." + contentsignals.KindPIIEmail,
	"content." + contentsignals.KindPIICard, "content." + contentsignals.KindPIINationalID,
	"content." + contentsignals.KindClassifierFlag,
}

// oneLine reports whether s is one line of 1..200 characters.
func oneLine(s string) bool {
	return strings.TrimSpace(s) != "" && !strings.ContainsAny(s, "\r\n") && len([]rune(s)) <= 200
}

// closure runs the D715 checks over the sources and returns every problem,
// sorted. An empty list is a closed map.
func closure(src sources, set *Set, f facts) []string {
	var bad []string
	fail := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }
	line := func(where, s, id string) {
		switch {
		case !oneLine(s):
			fail("%s: %q is not one line of 1..200 characters", where, s)
		case id != "" && !strings.Contains(s, "("+id+")"):
			fail("%s: %q does not cite (%s)", where, s, id)
		case bannedWord.MatchString(s):
			fail("%s: %q uses a banned word (D717)", where, s)
		}
	}
	// #2: every named id is a live technique of its catalog.
	known := func(where, id string) {
		fw, ok := catalog.FrameworkOf(id)
		if !ok {
			fail("%s: %s is no technique id", where, id)
			return
		}
		if rules.RetiredATLAS[id] {
			fail("%s: %s is a retired ATLAS id", where, id)
			return
		}
		t, ok := catalog.Load(fw).Technique(id)
		switch {
		case !ok:
			fail("%s: %s is not in the pinned %s catalog", where, id, fw)
		case t.Deprecated || t.Revoked:
			fail("%s: %s is deprecated or revoked in the pinned %s catalog", where, id, fw)
		}
	}
	tagged := func(where string, atlas, attack []string, why map[string]string, none string) {
		ids := joined(atlas, attack)
		for _, id := range ids {
			known(where, id)
		}
		// #3: ids or techniques_none.
		switch {
		case len(ids) == 0 && none == "":
			fail("%s: no technique and no techniques_none", where)
		case len(ids) > 0 && none != "":
			fail("%s: techniques and techniques_none", where)
		case none != "":
			line(where+" techniques_none", none, "")
		}
		// #6: one cited line per id, when the source carries lines.
		if why != nil {
			for _, id := range ids {
				line(where+" why "+id, why[id], id)
			}
			for id := range why {
				if !slices.Contains(ids, id) {
					fail("%s: why for %s, which is not tagged", where, id)
				}
			}
		}
	}

	for _, u := range set.Unknown() {
		fail("unknown id (D714a): %s", u)
	}

	// #4: Prevent controls.
	ids := map[string]bool{}
	for _, c := range src.prevent {
		where := c.ID
		switch {
		case !strings.HasPrefix(c.ID, "prevent.") || ids[c.ID]:
			fail("%s: id must be prevent.<slug> and unique", where)
		case !c.Surface.Valid() || !c.Requires.Valid():
			fail("%s: surface %q or requirement %q is not in the closed list", where, c.Surface, c.Requires)
		case len(c.Techniques) == 0 || len(c.HR) == 0:
			fail("%s: needs a technique and an HR id", where)
		}
		ids[c.ID] = true
		line(where+" title", c.Title, "")
		for _, hr := range c.HR {
			if !f.hr[hr] {
				fail("%s: %s is not in HARDENING_RULES.md", where, hr)
			}
		}
		for _, code := range c.ReasonCodes {
			if !f.reasons[code] {
				fail("%s: reason code %s is no constant of the decision code", where, code)
			}
		}
		tagged(where, c.Techniques, nil, c.Why, "")
		if c.Why == nil {
			fail("%s: no why lines", where)
		}
	}

	// #3: kinds are exactly the expected ones, each ids or None.
	if got := slices.Sorted(func(yield func(string) bool) {
		for k := range src.kinds {
			if !yield(k) {
				return
			}
		}
	}); !slices.Equal(got, slices.Sorted(slices.Values(expectedKinds))) {
		fail("kinds %v, want %v", got, expectedKinds)
	}
	for k, km := range src.kinds {
		why := km.Why
		if why == nil {
			why = map[string]string{}
		}
		tagged(k, km.ATLAS, km.ATTACK, why, km.None)
	}

	for _, r := range src.rules {
		tagged(r.ID, r.ATLAS, r.ATTACK, nil, r.TechniquesNone)
	}
	for id, e := range src.scenarios {
		why := e.TechniqueWhy
		if why == nil {
			why = map[string]string{}
		}
		tagged(id, e.ATLAS, e.ATTACK, why, e.TechniquesNone)
	}
	for id, e := range src.campaigns {
		why := e.TechniqueWhy
		if why == nil {
			why = map[string]string{}
		}
		tagged(id, e.ATLAS, e.ATTACK, why, e.TechniquesNone)
	}
	// Hub rules may carry no technique (custom rules have no
	// techniques_none); what they name is checked like the rest.
	for _, r := range src.hub.Rules {
		for _, id := range joined(r.ATLAS, r.ATTACK) {
			known(r.ID, id)
		}
	}

	// Outside and Unaddressed: closed enums, once each, on matrix cells.
	listed := map[string]string{}
	cell := func(where, id string) {
		known(where, id)
		if prev, ok := listed[id]; ok {
			fail("%s: %s is also in %s", where, id, prev)
		}
		listed[id] = where
		if fw, ok := catalog.FrameworkOf(id); ok {
			if t, ok := catalog.Load(fw).Technique(id); ok && t.Parent != "" {
				fail("%s: %s is a sub-technique; Outside and Unaddressed go on the parent", where, id)
			}
		}
	}
	for _, o := range src.outside {
		cell("outside", o.ID)
		if !o.Reason.Valid() || !o.CoveredBy.Valid() {
			fail("outside %s: reason %q or tool kind %q is not in the closed list", o.ID, o.Reason, o.CoveredBy)
		}
		if o.Note != "" {
			line("outside "+o.ID+" note", o.Note, "")
		}
	}
	for _, u := range src.unaddressed {
		cell("unaddressed", u.ID)
		line("unaddressed "+u.ID, u.Why, u.ID)
	}

	// #1: every matrix cell is exactly one of mapped, Outside, Unaddressed.
	for _, fw := range catalog.Frameworks() {
		c := catalog.Load(fw)
		m := set.Techniques(fw)
		for _, t := range c.Matrix() {
			mapped := m[t.ID].Mapped()
			for _, sub := range c.Subtechniques(t.ID) {
				mapped = mapped || m[sub.ID].Mapped()
			}
			n := 0
			for _, b := range []bool{mapped, m[t.ID].Outside != nil, m[t.ID].Unaddressed != nil} {
				if b {
					n++
				}
			}
			if n != 1 {
				fail("%s %s (%s): mapped %v, outside %v, unaddressed %v; want exactly one", fw, t.ID, t.Name, mapped, m[t.ID].Outside != nil, m[t.ID].Unaddressed != nil)
			}
		}
	}
	slices.Sort(bad)
	return slices.Compact(bad)
}

// readFacts reads the hardening rules and walks the decision code for its
// string constants (D715 #4, D714b Q2): internal/authority/...,
// internal/gateway/..., internal/grants/domain and the PAP error codes.
func readFacts(t *testing.T) facts {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join(root, "docs", "security", "HARDENING_RULES.md"))
	if err != nil {
		t.Fatal(err)
	}
	f := facts{hr: map[string]bool{}, reasons: map[string]bool{}}
	for _, m := range regexp.MustCompile(`(?m)^\| (HR-[0-9]{3}) \|`).FindAllStringSubmatch(string(doc), -1) {
		f.hr[m[1]] = true
	}
	if len(f.hr) < 100 {
		t.Fatalf("read %d hardening rules", len(f.hr))
	}
	consts := func(path string) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.CONST {
				continue
			}
			for _, s := range g.Specs {
				for _, v := range s.(*ast.ValueSpec).Values {
					if lit, ok := v.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if s, err := strconv.Unquote(lit.Value); err == nil {
							f.reasons[s] = true
						}
					}
				}
			}
		}
	}
	walk := func(dir string, recursive bool) {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return err
			case d.IsDir() && !recursive && path != filepath.Join(root, dir):
				return filepath.SkipDir
			case !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go"):
				consts(path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	walk("internal/authority", true)
	walk("internal/gateway", true)
	walk("internal/grants/domain", false)
	consts(filepath.Join(root, "internal", "identity", "pap", "pap.go"))
	return f
}

// TestHR683_TheThreatMapIsClosed is the closure test (G0 M28 D715): every
// matrix cell of both pinned catalogs is mapped, Outside or Unaddressed,
// every id is a live technique, and every line is honest.
// Covers: F974, HR-683, HR-682
func TestHR683_TheThreatMapIsClosed(t *testing.T) {
	src, err := shippedSources()
	if err != nil {
		t.Fatal(err)
	}
	set, err := build(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range closure(src, set, readFacts(t)) {
		t.Error(p)
	}
}

// TestT304_ARevokedOrRetiredIdBreaksTheClosure: a pinned catalog update
// that deprecates or revokes a mapped technique, or an ATLAS id the pinned
// release no longer has, fails the closure test instead of shifting the
// map in silence (G0 M28 D715 #2).
// Covers: F974, T-304, HR-682, HR-683
func TestT304_ARevokedOrRetiredIdBreaksTheClosure(t *testing.T) {
	f := readFacts(t)
	for name, c := range map[string]struct {
		edit func(*sources)
		want string
	}{
		"revoked ATT&CK id": {func(s *sources) { s.rules = []*rules.Rule{{ID: "pc.x.y", ATTACK: []string{"T1562.001"}}} }, "pc.x.y: T1562.001 is deprecated or revoked"},
		"retired ATLAS id":  {func(s *sources) { s.rules = []*rules.Rule{{ID: "pc.x.y", ATLAS: []string{"AML.T0057"}}} }, "pc.x.y: AML.T0057 is a retired ATLAS id"},
		"unknown id": {func(s *sources) {
			s.scenarios = map[string]library.Entry{"RT-001": {ATTACK: []string{"T9999"}, TechniqueWhy: map[string]string{"T9999": "x (T9999)"}}}
		}, "RT-001: T9999 is not in the pinned attack-enterprise catalog"},
		"not an id":            {func(s *sources) { s.campaigns = map[string]library.CampaignEntry{"RT-140": {ATLAS: []string{"X1"}}} }, "unknown id (D714a): RT-140: X1"},
		"neither ids nor none": {func(s *sources) { s.scenarios = map[string]library.Entry{"RT-001": {}} }, "RT-001: no technique and no techniques_none"},
		"uncited why": {func(s *sources) {
			s.scenarios = map[string]library.Entry{"RT-001": {ATTACK: []string{"T1059"}, TechniqueWhy: map[string]string{"T1059": "Runs a shell."}}}
		}, `does not cite (T1059)`},
		"banned word": {func(s *sources) {
			s.unaddressed = []mapping.UnaddressedEntry{{ID: "T1059", Why: "Shell (T1059): agents are safe here."}}
		}, "uses a banned word"},
		"HR that does not exist": {func(s *sources) {
			s.prevent = []mapping.PreventControl{{
				ID: "prevent.x", Title: "X", Surface: mapping.SurfaceAuthority, Requires: mapping.RequiresAlways, HR: []string{"HR-999"},
				Techniques: []string{"T1059"}, Why: map[string]string{"T1059": "x (T1059)"},
			}}
		}, "prevent.x: HR-999 is not in HARDENING_RULES.md"},
		"reason code that does not exist": {func(s *sources) {
			s.prevent = []mapping.PreventControl{{
				ID: "prevent.x", Title: "X", Surface: mapping.SurfaceAuthority, Requires: mapping.RequiresAlways, HR: []string{"HR-045"},
				ReasonCodes: []string{"NO_SUCH_CODE"}, Techniques: []string{"T1059"}, Why: map[string]string{"T1059": "x (T1059)"},
			}}
		}, "prevent.x: reason code NO_SUCH_CODE is no constant"},
		"sub-technique outside": {func(s *sources) {
			s.outside = []mapping.OutsideEntry{{ID: "T1059.001", Reason: mapping.OutsideEndpoint, CoveredBy: mapping.ToolEDR}}
		}, "outside: T1059.001 is a sub-technique"},
		"listed twice": {func(s *sources) {
			s.outside = []mapping.OutsideEntry{{ID: "T1059", Reason: mapping.OutsideEndpoint, CoveredBy: mapping.ToolEDR}}
			s.unaddressed = []mapping.UnaddressedEntry{{ID: "T1059", Why: "x (T1059)"}}
		}, "unaddressed: T1059 is also in outside"},
		"unlisted matrix cell": {func(s *sources) {}, "attack-enterprise T1059 (Command and Scripting Interpreter): mapped false, outside false, unaddressed false"},
	} {
		t.Run(name, func(t *testing.T) {
			src := sources{kinds: map[string]mapping.KindMapping{}}
			c.edit(&src)
			set, err := build(src)
			if err != nil {
				t.Fatal(err)
			}
			got := closure(src, set, f)
			if !slices.ContainsFunc(got, func(p string) bool { return strings.Contains(p, c.want) }) {
				t.Errorf("want a problem containing %q, got %d problems, first %q", c.want, len(got), first(got))
			}
		})
	}
	// The reason-code walk reaches the grant chain's codes (D714b Q2) and
	// the PAP error codes.
	for _, code := range []string{"NO_GRANT", "OUTSIDE_GUARDRAIL", "key_mismatch", "unknown_route", "CONSEQUENCE_UNKNOWN"} {
		if !f.reasons[code] {
			t.Errorf("the walk misses %s", code)
		}
	}
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

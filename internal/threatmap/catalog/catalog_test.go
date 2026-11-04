// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//nolint:misspell // MITRE is a proper noun (the ATT&CK and ATLAS publisher), and tools/mitre a path.
package catalog_test

import (
	"encoding/json/v2"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
)

type pin struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

func pins(t *testing.T) map[catalog.Framework]pin {
	t.Helper()
	b, err := os.ReadFile("../../../tools/mitre/pins.json")
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		ATTACK pin `json:"attack"`
		ATLAS  pin `json:"atlas"`
	}
	if err := json.Unmarshal(b, &p, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	return map[catalog.Framework]pin{catalog.FrameworkATTACK: p.ATTACK, catalog.FrameworkATLAS: p.ATLAS}
}

var shortNameRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Covers: F974, HR-682
func TestHR682_CatalogsLoadAndMatchTheirPins(t *testing.T) {
	p := pins(t)
	for _, f := range catalog.Frameworks() {
		t.Run(string(f), func(t *testing.T) {
			c := catalog.Load(f)
			switch {
			case c.Framework != f || c.Format != catalog.Format:
				t.Fatalf("framework %q format %q", c.Framework, c.Format)
			case c.Version != p[f].Version || c.SourceURL != p[f].URL || c.SourceSHA256 != p[f].SHA256:
				t.Errorf("catalog %s %s %s does not match pins.json %+v", c.Version, c.SourceURL, c.SourceSHA256, p[f])
			case c.Notice == "" || !strings.Contains(c.Notice, "MITRE"):
				t.Errorf("notice %q", c.Notice)
			case len(c.Tactics) == 0 || len(c.Matrix()) == 0:
				t.Fatal("no tactics or no matrix")
			}
			orders := map[int]bool{}
			shorts := map[string]bool{}
			for _, ta := range c.Tactics {
				if !shortNameRE.MatchString(ta.ShortName) || shorts[ta.ShortName] {
					t.Errorf("tactic %s: short name %q is not unique or not a slug", ta.ID, ta.ShortName)
				}
				if ta.Order < 1 || orders[ta.Order] {
					t.Errorf("tactic %s: order %d", ta.ID, ta.Order)
				}
				shorts[ta.ShortName], orders[ta.Order] = true, true
			}
			ids := map[string]bool{}
			for i, te := range c.Techniques {
				if i > 0 && c.Techniques[i-1].ID >= te.ID {
					t.Errorf("techniques not sorted by id at %s", te.ID)
				}
				ids[te.ID] = true
				for _, s := range te.Tactics {
					if !shorts[s] {
						t.Errorf("technique %s: unknown tactic %q", te.ID, s)
					}
				}
				if !te.Deprecated && !te.Revoked && len(te.Tactics) == 0 {
					t.Errorf("technique %s has no tactic", te.ID)
				}
				if f == catalog.FrameworkATLAS && (te.Deprecated || te.Revoked) {
					t.Errorf("ATLAS v6 has no deprecated or revoked flag, %s carries one", te.ID)
				}
				if fw, ok := catalog.FrameworkOf(te.ID); !ok || fw != f {
					t.Errorf("FrameworkOf(%s) = %q", te.ID, fw)
				}
			}
			for _, te := range c.Techniques {
				if te.Parent != "" && (!ids[te.Parent] || !strings.HasPrefix(te.ID, te.Parent+".")) {
					t.Errorf("sub-technique %s: parent %q", te.ID, te.Parent)
				}
			}
		})
	}
}

// Covers: F974, HR-682, T-304
func TestHR682_DigestIsStable(t *testing.T) {
	for _, f := range catalog.Frameworks() {
		d := catalog.Digest(f)
		if len(d) != 64 || d != catalog.Digest(f) || d != catalog.Load(f).Digest {
			t.Errorf("%s: digest %q is not stable", f, d)
		}
	}
	if catalog.Digest(catalog.FrameworkATLAS) == catalog.Digest(catalog.FrameworkATTACK) {
		t.Error("both catalogs share a digest")
	}
}

// Covers: F974, HR-682
func TestHR682_Lookups(t *testing.T) {
	attack := catalog.Load(catalog.FrameworkATTACK)
	ps, ok := attack.Technique("T1059.001")
	if !ok || ps.Parent != "T1059" {
		t.Fatalf("T1059.001 = %+v, %v", ps, ok)
	}
	if subs := attack.Subtechniques("T1059"); !slices.ContainsFunc(subs, func(s catalog.Technique) bool { return s.ID == "T1059.001" }) {
		t.Error("T1059 lacks its sub-technique T1059.001")
	}
	if ta, ok := attack.Tactic("execution"); !ok || ta.ID != "TA0002" {
		t.Errorf("tactic execution = %+v", ta)
	}
	for _, m := range attack.Matrix() {
		if m.Parent != "" || m.Deprecated || m.Revoked {
			t.Errorf("matrix cell %s is a sub-technique, deprecated or revoked", m.ID)
		}
	}
	if !catalog.KnownATTACK("T1059") || catalog.KnownATTACK("AML.T0051") || catalog.KnownATTACK("T9999") {
		t.Error("KnownATTACK")
	}
	if !catalog.KnownATLAS("AML.T0051") || catalog.KnownATLAS("T1059") || catalog.KnownATLAS("AML.T9999") {
		t.Error("KnownATLAS")
	}
	if !catalog.Known("AML.T0051") || !catalog.Known("T1059") || catalog.Known("X1") {
		t.Error("Known")
	}
	if _, ok := catalog.FrameworkOf("ASI01"); ok {
		t.Error("FrameworkOf took an OWASP id")
	}
	// Deprecated and revoked ids stay known, so stored rules keep parsing.
	for _, te := range attack.Techniques {
		if (te.Deprecated || te.Revoked) && (!catalog.KnownATTACK(te.ID) || attack.Active(te.ID)) {
			t.Errorf("%s: deprecated or revoked ids are known and not active", te.ID)
		}
		if catalog.KnownActive(te.ID) != attack.Active(te.ID) {
			t.Errorf("%s: KnownActive disagrees with Active", te.ID)
		}
	}
	// G0 M28 D714e L5: KnownActive is what --technique accepts.
	if !catalog.KnownActive("T1685") || !catalog.KnownActive("AML.T0051") || catalog.KnownActive("T1562.001") || catalog.KnownActive("X1") || catalog.KnownActive("T9999") {
		t.Error("KnownActive")
	}
}

// Covers: F974, HR-682
func TestHR682_LoadPanicsOnUnknownFramework(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Load accepted an unknown framework")
		}
	}()
	catalog.Load("mobile-attack")
}

// TestHR682_AccessorsReturnCopies: what Load and the lookups return is the
// caller's own, so no caller can change the pinned catalog (G0 M28 D714c L5).
// Covers: F974, HR-682
func TestHR682_AccessorsReturnCopies(t *testing.T) {
	a := catalog.Load(catalog.FrameworkATTACK)
	a.Techniques[0].ID = "changed"
	a.Tactics[0].Name = "changed"
	te, _ := a.Technique("T1059.001")
	te.Tactics[0] = "changed"
	a.Subtechniques("T1059")[0].Tactics[0] = "changed"
	a.Matrix()[0].Platforms = nil

	b := catalog.Load(catalog.FrameworkATTACK)
	if b.Techniques[0].ID == "changed" || b.Tactics[0].Name == "changed" {
		t.Error("Load shares its slices")
	}
	for _, id := range []string{"T1059.001", b.Subtechniques("T1059")[0].ID} {
		if te, _ := b.Technique(id); slices.Contains(te.Tactics, "changed") {
			t.Errorf("%s: a lookup shares its tactics", id)
		}
	}
	if !catalog.KnownATTACK(b.Techniques[0].ID) {
		t.Error("the shared index changed")
	}
}

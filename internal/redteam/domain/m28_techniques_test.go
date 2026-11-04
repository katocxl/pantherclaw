// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

const techniqueWhy = "technique_why:\n" +
	"  AML.T0051.001: \"Indirect prompt injection (AML.T0051.001): the issue carries the instruction.\"\n" +
	"  T1078: \"Valid accounts (T1078): it tries the agent's own credential.\"\n"

const techniques = "atlas: [AML.T0051.001]\nattack: [T1078]\n" + techniqueWhy

// Covers: F974, HR-683
func TestHR683_ScenarioTechniquesComeFromTheCatalogueWithAReason(t *testing.T) {
	s, err := domain.Parse(asiFile("RT-901", techniques))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.ATLAS) != 1 || len(s.ATTACK) != 1 || len(s.TechniqueWhy) != 2 {
		t.Fatalf("techniques: %v %v %v", s.ATLAS, s.ATTACK, s.TechniqueWhy)
	}
	// A library scenario that tests PantherClaw itself says so (G0 M28 D714b).
	if s, err := domain.Parse(asiFile("RT-901", "techniques_none: \"Tests the export of PantherClaw's own evidence.\"\n")); err != nil || s.TechniquesNone == "" {
		t.Fatalf("techniques_none: %v", err)
	}
	const (
		notInCatalog = "not a technique of the pinned catalog"
		oneEach      = "one reason for each"
		oneLine      = "must be one line"
	)
	for _, c := range []struct{ name, tags, want string }{
		{"unknown ATLAS", "atlas: [AML.T9999]\ntechnique_why:\n  AML.T9999: \"x (AML.T9999)\"\n", notInCatalog},
		{"unknown ATT&CK", "attack: [T9999]\ntechnique_why:\n  T9999: \"x (T9999)\"\n", notInCatalog},
		{"ATT&CK as ATLAS", "atlas: [T1078]\ntechnique_why:\n  T1078: \"x (T1078)\"\n", notInCatalog},
		{"ATLAS as ATT&CK", "attack: [AML.T0051]\ntechnique_why:\n  AML.T0051: \"x (AML.T0051)\"\n", notInCatalog},
		{"repeated", "attack: [T1078, T1078]\ntechnique_why:\n  T1078: \"x (T1078)\"\n", "duplicate"},
		{"no reason", "atlas: [AML.T0051.001]\nattack: [T1078]\n", oneEach},
		{"missing reason", "atlas: [AML.T0051.001]\nattack: [T1078]\ntechnique_why:\n  T1078: \"x (T1078)\"\n", oneEach},
		{"reason for other", "attack: [T1078]\ntechnique_why:\n  T1078: \"x (T1078)\"\n  T1059: \"x (T1059)\"\n", oneEach},
		{"reason, no id", "attack: [T1078]\ntechnique_why:\n  T1059: \"x (T1059)\"\n", "gives no reason for T1078"},
		{"no citation", "attack: [T1078]\ntechnique_why:\n  T1078: \"Valid accounts: its credential.\"\n", "must cite"},
		{"two lines", "attack: [T1078]\ntechnique_why:\n  T1078: \"x (T1078)\\ny\"\n", oneLine},
		{"too long", "attack: [T1078]\ntechnique_why:\n  T1078: \"(T1078) " + strings.Repeat("x", 200) + "\"\n", oneLine},
		{"blank", "attack: [T1078]\ntechnique_why:\n  T1078: \" \"\n", oneLine},
		{"retired ATLAS id", "atlas: [AML.T0057]\ntechnique_why:\n  AML.T0057: \"x (AML.T0057)\"\n", notInCatalog},
		{"why without a tag", "technique_why:\n  T1078: \"x (T1078)\"\n", oneEach},
		{"none beside ids", "attack: [T1078]\ntechnique_why:\n  T1078: \"x (T1078)\"\ntechniques_none: \"Tests the export.\"\n", "techniques_none replaces"},
		{"none beside a reason", "technique_why:\n  T1078: \"x (T1078)\"\ntechniques_none: \"Tests the export.\"\n", "techniques_none replaces"},
		{"none on two lines", "techniques_none: \"Tests\\nthe export.\"\n", "techniques_none must be one line"},
		{"none too long", "techniques_none: \"" + strings.Repeat("x", 201) + "\"\n", "techniques_none must be one line"},
		{"none blank", "techniques_none: \" \"\n", "techniques_none must be one line"},
	} {
		_, err := domain.Parse(asiFile("RT-901", c.tags))
		if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want the %q check", c.name, err, c.want)
		}
	}
}

// TestHR685_CustomerScenarioCarriesNoTechnique: a customer-authored (CX)
// scenario is the customer's word, so it cannot say which ATLAS or ATT&CK technique
// it tests; only PantherClaw's library scenarios feed the threat map.
// Covers: F974, HR-685
func TestHR685_CustomerScenarioCarriesNoTechnique(t *testing.T) {
	cx := func(tags string) []byte {
		return []byte(strings.Replace(string(asiFile("CX-901", tags)), "tier: community", "tier: business", 1))
	}
	if _, err := domain.Parse(cx("")); err != nil {
		t.Fatalf("the customer scenario without techniques must parse: %v", err)
	}
	for name, tags := range map[string]string{
		"atlas":         "atlas: [AML.T0051.001]\ntechnique_why:\n  AML.T0051.001: \"x (AML.T0051.001)\"\n",
		"attack":        "attack: [T1078]\ntechnique_why:\n  T1078: \"x (T1078)\"\n",
		"both":          techniques,
		"only a reason": "technique_why:\n  T1078: \"x (T1078)\"\n",
		"none":          "techniques_none: \"Tests the export.\"\n",
	} {
		_, err := domain.Parse(cx(tags))
		if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "techniques are for library scenarios") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

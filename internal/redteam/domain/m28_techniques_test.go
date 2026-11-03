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
	for name, bad := range map[string]string{
		"unknown ATLAS":     "atlas: [AML.T9999]\ntechnique_why:\n  AML.T9999: \"x (AML.T9999)\"\n",
		"unknown ATT&CK":    "attack: [T9999]\ntechnique_why:\n  T9999: \"x (T9999)\"\n",
		"ATT&CK as ATLAS":   "atlas: [T1078]\ntechnique_why:\n  T1078: \"x (T1078)\"\n",
		"ATLAS as ATT&CK":   "attack: [AML.T0051]\ntechnique_why:\n  AML.T0051: \"x (AML.T0051)\"\n",
		"repeated":          "attack: [T1078, T1078]\ntechnique_why:\n  T1078: \"x (T1078)\"\n",
		"no reason":         "atlas: [AML.T0051.001]\nattack: [T1078]\n",
		"missing reason":    "atlas: [AML.T0051.001]\nattack: [T1078]\ntechnique_why:\n  T1078: \"x (T1078)\"\n",
		"reason for other":  "attack: [T1078]\ntechnique_why:\n  T1078: \"x (T1078)\"\n  T1059: \"x (T1059)\"\n",
		"reason, no id":     "attack: [T1078]\nattack: []\n",
		"no citation":       "attack: [T1078]\ntechnique_why:\n  T1078: \"Valid accounts: its credential.\"\n",
		"two lines":         "attack: [T1078]\ntechnique_why:\n  T1078: \"x (T1078)\\ny\"\n",
		"too long":          "attack: [T1078]\ntechnique_why:\n  T1078: \"(T1078) " + strings.Repeat("x", 200) + "\"\n",
		"blank":             "attack: [T1078]\ntechnique_why:\n  T1078: \" \"\n",
		"retired ATLAS id":  "atlas: [AML.T0057]\ntechnique_why:\n  AML.T0057: \"x (AML.T0057)\"\n",
		"why without a tag": "technique_why:\n  T1078: \"x (T1078)\"\n",
	} {
		if _, err := domain.Parse(asiFile("RT-901", bad)); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR685_CustomerScenarioCarriesNoTechnique: a customer-authored (CX)
// scenario is the customer's word, so it cannot say which MITRE technique
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
	} {
		_, err := domain.Parse(cx(tags))
		if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "techniques are for library scenarios") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

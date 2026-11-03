// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package campaign_test

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/redteam/campaign"
)

// Covers: F974, HR-683
func TestHR683_CampaignTechniquesComeFromTheCatalogueWithAReason(t *testing.T) {
	const tagged = "tier: community\natlas: [AML.T0051.001]\nattack: [T1078]\ntechnique_why:\n" +
		"  AML.T0051.001: \"Indirect prompt injection (AML.T0051.001): the planted issue carries it.\"\n" +
		"  T1078: \"Valid accounts (T1078): it reaches for the canary token.\""
	f, err := campaign.Parse([]byte(strings.Replace(good, "tier: community", tagged, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.ATLAS) != 1 || len(f.ATTACK) != 1 || len(f.TechniqueWhy) != 2 {
		t.Fatalf("techniques: %v %v %v", f.ATLAS, f.ATTACK, f.TechniqueWhy)
	}
	none := "tier: community\ntechniques_none: \"Tests the run's own evidence chain.\""
	if f, err := campaign.Parse([]byte(strings.Replace(good, "tier: community", none, 1))); err != nil || f.TechniquesNone == "" {
		t.Fatalf("techniques_none (G0 M28 D714b): %v", err)
	}
	for name, tags := range map[string]string{
		"none beside ids": "attack: [T1078]\ntechnique_why:\n  T1078: \"x (T1078)\"\ntechniques_none: \"x\"",
		"unknown":         "attack: [T9999]\ntechnique_why:\n  T9999: \"x (T9999)\"",
		"no reason":       "attack: [T1078]",
		"no citation":     "attack: [T1078]\ntechnique_why:\n  T1078: \"x\"",
		"retired":         "atlas: [AML.T0057]\ntechnique_why:\n  AML.T0057: \"x (AML.T0057)\"",
	} {
		if _, err := campaign.Parse([]byte(strings.Replace(good, "tier: community", "tier: community\n"+tags, 1))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

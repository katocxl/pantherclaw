// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package library_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/campaign"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
)

var update = flag.Bool("update", false, "rewrite library.json from redteam/scenarios")

const dir = "../../../redteam/scenarios"

// TestLibrary_MatchesTheShippedScenarios: the embedded map is exactly the
// id, digest and tier of every shipped scenario (D125, HR-467). Run with
// -update (task range:library) after changing a scenario.
// Covers: PN-009.6
func TestLibrary_MatchesTheShippedScenarios(t *testing.T) {
	set, err := app.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]library.Entry{}
	for _, l := range set {
		want[l.Scenario.ID] = library.Entry{
			Digest: l.Digest, Tier: l.Scenario.Tier, ASI: l.Scenario.ASI, ASIWhy: l.Scenario.ASIWhy,
			ATLAS: l.Scenario.ATLAS, ATTACK: l.Scenario.ATTACK, TechniqueWhy: l.Scenario.TechniqueWhy, TechniquesNone: l.Scenario.TechniquesNone,
		}
	}
	if *update {
		b, err := json.Marshal(want, json.Deterministic(true), jsontext.WithIndent("  "))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("library.json", append(b, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	same := func(a, b library.Entry) bool {
		return a.Digest == b.Digest && a.Tier == b.Tier && slices.Equal(a.ASI, b.ASI) && maps.Equal(a.ASIWhy, b.ASIWhy) &&
			slices.Equal(a.ATLAS, b.ATLAS) && slices.Equal(a.ATTACK, b.ATTACK) && maps.Equal(a.TechniqueWhy, b.TechniqueWhy) && a.TechniquesNone == b.TechniquesNone
	}
	if got := library.All(); !maps.EqualFunc(got, want, same) {
		t.Fatalf("library.json is out of date with %s: run task range:library", dir)
	}
	if len(want) < 30 {
		t.Fatalf("the library holds %d scenarios, want at least 30", len(want))
	}
}

// TestD304_TagsAreKnownRisks: every tag is a listed risk. ASI05 is only on
// the scenarios that run code in the sandbox (D529), and no scenario tags
// ASI06: none poisons memory or context, so it reads as a gap.
// Covers: F898
func TestD304_TagsAreKnownRisks(t *testing.T) {
	tagged := 0
	for id, e := range library.All() {
		if len(e.ASI) > 0 {
			tagged++
		}
		if len(e.ASIWhy) != len(e.ASI) {
			t.Errorf("%s: %d tags and %d reasons (D531)", id, len(e.ASI), len(e.ASIWhy))
		}
		for _, tag := range e.ASI {
			if !strings.Contains(e.ASIWhy[tag], "("+tag+")") {
				t.Errorf("%s: the reason for %s does not cite the risk: %q", id, tag, e.ASIWhy[tag])
			}
			if !rules.KnownOWASP(tag) {
				t.Errorf("%s: tag %q", id, tag)
			}
			if tag == "ASI06" || (tag == "ASI05" && id != "RT-014" && id != "RT-015") {
				t.Errorf("%s: %s is not what this scenario exercises (D304, D529)", id, tag)
			}
		}
	}
	if tagged == 0 {
		t.Fatal("no scenario is tagged")
	}
}

const campaignDir = "../../../redteam/campaigns"

// TestLibrary_MatchesTheShippedCampaigns: the embedded campaigns are exactly
// the id, digest, tier and attempts of every shipped campaign file (G0 M25
// D310): the server derives outcomes from these attempts, never from the
// runner's (HR-608). Run with -update (task range:library) after changing a
// campaign.
// Covers: F900
func TestLibrary_MatchesTheShippedCampaigns(t *testing.T) {
	set, err := campaign.LoadDir(campaignDir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]library.CampaignEntry{}
	for _, l := range set {
		want[l.File.ID] = library.CampaignEntry{
			Digest: l.Digest, Tier: l.File.Tier, Attempts: l.File.Attempts, ASI: l.File.ASI,
			ATLAS: l.File.ATLAS, ATTACK: l.File.ATTACK, TechniqueWhy: l.File.TechniqueWhy, TechniquesNone: l.File.TechniquesNone,
		}
	}
	if *update {
		b, err := json.Marshal(want, json.Deterministic(true), jsontext.WithIndent("  "))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("campaigns.json", append(b, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	techniques := map[string]bool{}
	for _, l := range set {
		got, ok := library.Campaign(l.File.ID)
		if !ok || got.Digest != l.Digest || got.Tier != l.File.Tier || !slices.Equal(got.Attempts, l.File.Attempts) ||
			!slices.Equal(got.ASI, l.File.ASI) || !slices.Equal(got.ATLAS, l.File.ATLAS) || !slices.Equal(got.ATTACK, l.File.ATTACK) ||
			!maps.Equal(got.TechniqueWhy, l.File.TechniqueWhy) || got.TechniquesNone != l.File.TechniquesNone {
			t.Fatalf("campaigns.json is out of date with %s (%s): run task range:library", campaignDir, l.File.ID)
		}
		// The lookup S25a's compliance adapter calls gives the file's tags
		// (D529), and a copy.
		if asi := library.CampaignASI(l.File.ID); !slices.Equal(asi, l.File.ASI) {
			t.Fatalf("CampaignASI(%s) = %v, want %v", l.File.ID, asi, l.File.ASI)
		} else if len(asi) > 0 {
			asi[0] = "changed"
			if library.CampaignASI(l.File.ID)[0] == "changed" {
				t.Fatal("CampaignASI shares the library's slice")
			}
		}
		techniques[l.File.Technique] = true
	}
	for id := range 10 {
		if _, ok := library.Campaign(fmt.Sprintf("RT-14%d", id)); ok && !slices.ContainsFunc(set, func(l campaign.Loaded) bool { return l.File.ID == fmt.Sprintf("RT-14%d", id) }) {
			t.Fatalf("campaigns.json holds RT-14%d, which has no file", id)
		}
	}
	if library.CampaignASI("RT-999") != nil || len(library.CampaignASI("RT-140")) == 0 {
		t.Fatal("CampaignASI of an unknown id, or of a tagged campaign")
	}
	if len(set) != 10 || len(techniques) != len(campaign.Techniques) {
		t.Fatalf("the library holds %d campaigns over %d techniques, want RT-140..RT-149 over all %d", len(set), len(techniques), len(campaign.Techniques))
	}
}

// Covers: F974, HR-683
func TestLibrary_ByTechniqueFollowsTheTagsAndTheirParents(t *testing.T) {
	all := library.All()
	for id, e := range all {
		for _, tag := range append(slices.Clone(e.ATLAS), e.ATTACK...) {
			parent, _, _ := strings.Cut(strings.TrimPrefix(tag, "AML."), ".")
			if strings.HasPrefix(tag, "AML.") {
				parent = "AML." + parent
			}
			for _, q := range []string{tag, parent} {
				if got := library.ByTechnique(q); !slices.Contains(got, id) || !slices.IsSorted(got) {
					t.Errorf("ByTechnique(%s) = %v, want it to hold %s, sorted", q, got, id)
				}
			}
		}
	}
	if got := library.ByTechnique("T9999"); len(got) != 0 {
		t.Errorf("ByTechnique of an unknown id = %v", got)
	}
	// A prefix of an id is not its parent: T105 matches neither T1059 nor T1059.001.
	if got := library.ByTechnique("T105"); len(got) != 0 {
		t.Errorf("ByTechnique(T105) = %v", got)
	}
}

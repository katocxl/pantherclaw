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
	rtdomain "github.com/katocxl/pantherclaw/internal/redteam/domain"
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
		want[l.Scenario.ID] = library.Entry{Digest: l.Digest, Tier: l.Scenario.Tier, ASI: l.Scenario.ASI, ASIWhy: l.Scenario.ASIWhy}
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
		return a.Digest == b.Digest && a.Tier == b.Tier && slices.Equal(a.ASI, b.ASI) && maps.Equal(a.ASIWhy, b.ASIWhy)
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

// TestT283_ARetaggedFileKeepsTheLibraryDigestAndAnEditedOneLosesIt: a
// shipped scenario or campaign with other tags or wording still matches the
// library's digest, so earlier results stay mapped; one that runs something
// else no longer does, so the server refuses it as not the library's
// (HR-467, HR-608, ADR-0051).
func TestT283_ARetaggedFileKeepsTheLibraryDigestAndAnEditedOneLosesIt(t *testing.T) {
	set, err := app.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range set {
		e, ok := library.Lookup(l.Scenario.ID)
		if !ok || e.Digest != l.Digest {
			t.Fatalf("%s: not the library's digest: run task range:library", l.Scenario.ID)
		}
		s := l.Scenario
		s.Title, s.Threats, s.Rules, s.ASI, s.ASIWhy = s.Title+" (reworded)", append(slices.Clone(s.Threats), "T-283"), nil, []string{"ASI10"}, nil
		if d, _ := rtdomain.Digest(&s); d != e.Digest {
			t.Errorf("%s: a retagged scenario lost the library's digest", s.ID)
		}
		s.Steps = slices.Clone(s.Steps)
		s.Steps[len(s.Steps)-1].ID += "x"
		if d, _ := rtdomain.Digest(&s); d == e.Digest {
			t.Errorf("%s: an edited step kept the library's digest", s.ID)
		}
	}
	campaigns, err := campaign.LoadDir(campaignDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range campaigns {
		e, ok := library.Campaign(l.File.ID)
		if !ok || e.Digest != l.Digest {
			t.Fatalf("%s: not the library's digest: run task range:library", l.File.ID)
		}
		f := l.File
		f.Title, f.Technique, f.Threats, f.ASI, f.Rules = f.Title+" (reworded)", "fake_approver", nil, []string{"ASI10"}, nil
		if d, _ := campaign.Digest(&f); d != e.Digest {
			t.Errorf("%s: a retagged campaign lost the library's digest", f.ID)
		}
		f.Attempts = slices.Clone(f.Attempts)
		f.Attempts[0].Boundary = "HR-001"
		if d, _ := campaign.Digest(&f); d == e.Digest {
			t.Errorf("%s: an edited attempt kept the library's digest", f.ID)
		}
	}
	if len(set) < 30 || len(campaigns) != 10 {
		t.Fatalf("%d scenarios and %d campaigns", len(set), len(campaigns))
	}
}

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
		want[l.File.ID] = library.CampaignEntry{Digest: l.Digest, Tier: l.File.Tier, Attempts: l.File.Attempts, ASI: l.File.ASI}
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
			!slices.Equal(got.ASI, l.File.ASI) {
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

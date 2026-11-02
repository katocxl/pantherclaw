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
	"testing"

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
		want[l.Scenario.ID] = library.Entry{Digest: l.Digest, Tier: l.Scenario.Tier}
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
	if got := library.All(); !maps.Equal(got, want) {
		t.Fatalf("library.json is out of date with %s: run task range:library", dir)
	}
	if len(want) < 30 {
		t.Fatalf("the library holds %d scenarios, want at least 30", len(want))
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

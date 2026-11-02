// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package library_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"maps"
	"os"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
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
		want[l.Scenario.ID] = library.Entry{Digest: l.Digest, Tier: l.Scenario.Tier, ASI: l.Scenario.ASI}
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
		return a.Digest == b.Digest && a.Tier == b.Tier && slices.Equal(a.ASI, b.ASI)
	}
	if got := library.All(); !maps.EqualFunc(got, want, same) {
		t.Fatalf("library.json is out of date with %s: run task range:library", dir)
	}
	if len(want) < 30 {
		t.Fatalf("the library holds %d scenarios, want at least 30", len(want))
	}
}

// TestD304_TagsAreKnownRisks: every tag is a listed risk, and no scenario
// tags ASI05 or ASI06, which read as gaps until a real source maps them.
// Covers: F898
func TestD304_TagsAreKnownRisks(t *testing.T) {
	tagged := 0
	for id, e := range library.All() {
		if len(e.ASI) > 0 {
			tagged++
		}
		for _, tag := range e.ASI {
			if !rules.KnownOWASP(tag) {
				t.Errorf("%s: tag %q", id, tag)
			}
			if tag == "ASI05" || tag == "ASI06" {
				t.Errorf("%s: %s needs a real source (D304)", id, tag)
			}
		}
	}
	if tagged == 0 {
		t.Fatal("no scenario is tagged")
	}
}

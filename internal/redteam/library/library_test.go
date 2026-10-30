// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package library_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"maps"
	"os"
	"testing"

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

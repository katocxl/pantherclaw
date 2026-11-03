// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	rtapp "github.com/katocxl/pantherclaw/internal/redteam/app"
)

// TestHR683_RunByTechniqueKeepsTheLibraryScenariosThatTestIt: --technique
// runs only the scenarios library.ByTechnique names, sub-techniques
// included; none is exit 2 (G0 M28 D725).
// Covers: F974, HR-683
func TestHR683_RunByTechniqueKeepsTheLibraryScenariosThatTestIt(t *testing.T) {
	set := loaded("RT-001", "RT-004", "RT-012", "RT-020")
	got, err := byTechnique(set, "T1552") // RT-004 tags T1552.001
	if err != nil {
		t.Fatal(err)
	}
	ids := func(l []rtapp.Loaded) (out []string) {
		for _, x := range l {
			out = append(out, x.Scenario.ID)
		}
		return out
	}
	if !slices.Equal(ids(got), []string{"RT-004"}) {
		t.Errorf("T1552 ran %v, want RT-004", ids(got))
	}
	if got, err := byTechnique(set, "AML.T0091.000"); err != nil || !slices.Equal(ids(got), []string{"RT-012"}) {
		t.Errorf("AML.T0091.000 ran %v, %v", ids(got), err)
	}
	var ee *exitError
	_, err = byTechnique(set, "T1059") // no scenario of this set tests it
	if !errors.As(err, &ee) || ee.code != 2 || !strings.Contains(ee.msg, "no library scenario tests T1059") {
		t.Errorf("T1059: %v", err)
	}
	if _, err := byTechnique(loaded("CX-001"), "T1552"); err == nil {
		t.Error("a customer scenario ran for a technique")
	}
}

// TestHR682_RunByTechniqueRefusesAnUnknownId: an id outside both pinned
// catalogs is a usage error before anything loads (G0 M28 D725).
// Covers: F974, HR-682
func TestHR682_RunByTechniqueRefusesAnUnknownId(t *testing.T) {
	for _, id := range []string{"T9999", "AML.T9999", "ASI01", "t1059"} {
		var stderr bytes.Buffer
		err := redteamRun(context.Background(), &app{stderr: &stderr},
			[]string{"--scenarios", t.TempDir(), "--workload-file", "k.json", "--gateway", "https://gw.example", "--technique", id})
		if !errors.Is(err, errUsage) || !strings.Contains(stderr.String(), "is not a technique of the pinned ATLAS or ATT&CK catalogs") {
			t.Errorf("%s: %v %q", id, err, stderr.String())
		}
	}
}

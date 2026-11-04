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

// TestHR682_RunByTechniqueRefusesARevokedId: a revoked or deprecated id
// is in the catalog but is a usage error, not "no scenario" (G0 M28 D714e
// L5).
// Covers: F974, HR-682
func TestHR682_RunByTechniqueRefusesARevokedId(t *testing.T) {
	var stderr bytes.Buffer
	err := redteamRun(context.Background(), &app{stderr: &stderr},
		[]string{"--scenarios", t.TempDir(), "--workload-file", "k.json", "--gateway", "https://gw.example", "--technique", "T1562.001"})
	if !errors.Is(err, errUsage) || !strings.Contains(stderr.String(), "is revoked or deprecated in the pinned catalog") {
		t.Errorf("T1562.001: %v %q", err, stderr.String())
	}
}

// TestHR683_RunByTechniqueNamesTheTechniqueWhenTheSuiteRemovesEveryMatch:
// --technique with a --suite that drops every match still says which
// technique has no scenario, and exits 2 (G0 M28 D714e L5).
// Covers: F974, HR-683
func TestHR683_RunByTechniqueNamesTheTechniqueWhenTheSuiteRemovesEveryMatch(t *testing.T) {
	set := loaded("RT-004", "RT-150")
	set[0].Scenario.Suite, set[1].Scenario.Suite = "coding-agent", "platform"
	if got, err := ofSuite(set, "platform", "T1552", "dir"); err != nil || len(got) != 1 || got[0].Scenario.ID != "RT-150" {
		t.Errorf("platform: %v %v", got, err)
	}
	if got, err := ofSuite(set, "all", "", "dir"); err != nil || len(got) != 2 {
		t.Errorf("all: %v %v", got, err)
	}
	var ee *exitError
	_, err := ofSuite(set[:1], "platform", "T1552", "dir")
	if !errors.As(err, &ee) || ee.code != 2 || ee.msg != "pclaw: no library scenario tests T1552 in suite platform" {
		t.Errorf("technique: %v", err)
	}
	_, err = ofSuite(set[:1], "platform", "", "dir")
	if !errors.As(err, &ee) || ee.code != 2 || ee.msg != "pclaw: no scenarios of suite platform in dir" {
		t.Errorf("no technique: %v", err)
	}
}

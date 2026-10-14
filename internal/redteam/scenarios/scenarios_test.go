// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package scenarios_test checks the shipped range scenarios (redteam/scenarios).
package scenarios_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

const dir = "../../../redteam/scenarios"

// TestRange_EveryScenarioParses: every shipped scenario file is strict data
// that parses and validates, carries the id in its filename, and the
// catalogue holds at least 30 scenarios with unique ids (HR-223).
func TestRange_EveryScenarioParses(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(dir, "RT-*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	digests := map[string]string{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s, err := domain.Parse(raw)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
			continue
		}
		if err := s.Validate(); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
		if err := s.CheckFileName(filepath.Base(f)); err != nil {
			t.Error(err)
		}
		if seen[s.ID] {
			t.Errorf("%s is defined twice", s.ID)
		}
		seen[s.ID] = true
		if (s.Suite == "coding-agent") != (s.Tier == "community") {
			t.Errorf("%s: suite %s with tier %s", s.ID, s.Suite, s.Tier)
		}
		d, err := domain.Digest(s)
		if err != nil {
			t.Errorf("%s: digest: %v", s.ID, err)
		}
		digests[s.ID] = d
	}
	if len(files) < 30 {
		t.Fatalf("%d scenarios, want at least 30", len(files))
	}
	if domain.SetDigest(digests) == "" {
		t.Fatal("no set digest")
	}
}

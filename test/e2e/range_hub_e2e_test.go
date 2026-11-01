// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	hubdomain "github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/hub/seed"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// TestRange_ScenariosHubSeed runs the Hub's range scenarios as pclaw would:
// each written to a directory under its own file name, loaded from there and
// run in a stack of its own against the simulators. Each reaches the verdict
// and the steps its tests/expect.yaml states. It is part of `task range`.
//
// Covers: F849
func TestRange_ScenariosHubSeed(t *testing.T) {
	items, err := seed.Load(os.DirFS("../../hub"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	want := map[string][]byte{}
	for _, it := range items {
		if it.Entry.Kind != hubdomain.KindRangeScenario {
			continue
		}
		body, err := it.Item.DecodeBody()
		if err != nil {
			t.Fatal(err)
		}
		b := body.(hubdomain.RangeScenarioBody)
		if err := os.WriteFile(filepath.Join(dir, b.FileName), []byte(b.Scenario), 0o600); err != nil {
			t.Fatal(err)
		}
		want[b.FileName] = it.Tests["expect.yaml"]
	}
	set, err := app.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 5 {
		t.Fatalf("%d scenarios, want 5", len(set))
	}
	for _, l := range set {
		t.Run(l.Scenario.ID, func(t *testing.T) {
			var e struct {
				Verdict string   `json:"verdict"`
				Steps   []string `json:"steps"`
			}
			doc, err := domain.ToJSON(want[filepath.Base(l.File)])
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(doc, &e); err != nil {
				t.Fatal(err)
			}
			r := &app.Runner{Driver: newRangeDriver(t), Timeout: 5 * time.Minute}
			res := r.Run(context.Background(), l.Scenario)
			if string(res.Verdict) != e.Verdict {
				t.Errorf("%s: %s, want %s: %s", l.Scenario.ID, res.Verdict, e.Verdict, res.Detail)
			}
			var steps []string
			for _, st := range res.Steps {
				steps = append(steps, st.StepID)
				if !st.Matched {
					t.Logf("step %s: expected %+v observed %s/%s/%s: %s", st.StepID, st.Expect, st.Observed.Outcome, st.Observed.Reason, st.Observed.Code, st.Mismatch)
				}
			}
			if !slices.Equal(steps, e.Steps) {
				t.Errorf("ran %v, want %v", steps, e.Steps)
			}
		})
	}
}

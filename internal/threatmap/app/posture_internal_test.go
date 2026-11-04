// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
)

// TestHR680_TestFailedIsSinceTheFailingResult: a threatmap_test_failed
// finding is since the failing result's time, the earliest when two
// techniques name the scenario, not since the read (G0 M28 D720c, D724a).
// Covers: F971, HR-680, HR-689
func TestHR680_TestFailedIsSinceTheFailingResult(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	failed := func(id string, at time.Time) domain.Technique {
		return domain.Technique{ID: id, Test: domain.TestLane{State: domain.TestFailed, Scenarios: []domain.ScenarioRow{
			{ScenarioID: "RT-001", State: domain.TestFailed, Verdict: "FAIL", RecordedAt: at},
		}}}
	}
	early, late := now.Add(-5*24*time.Hour), now.Add(-2*24*time.Hour)
	targets := map[string]*target{}
	collect(targets, failed("AML.T0051", late), nil)
	collect(targets, failed("AML.T0054", early), nil)
	tg, ok := targets[KindTestFailed+":scenario:RT-001"]
	if !ok || len(targets) != 1 {
		t.Fatalf("targets %v", targets)
	}
	f := finding(tg, now)
	if f.Kind != KindTestFailed || !f.Since.Equal(early) || f.Detail["techniques"] != "AML.T0051, AML.T0054" {
		t.Errorf("finding %+v", f)
	}
}

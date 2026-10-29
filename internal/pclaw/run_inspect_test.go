// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"slices"
	"testing"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestRunInspectSections: --section takes repeated and comma-separated
// names, and refuses an unknown one.
// Covers: F224
func TestRunInspectSections(t *testing.T) {
	req, err := inspectRequest("r", []string{"budget,gaps", "lineage"}, 900, "tok")
	if err != nil {
		t.Fatal(err)
	}
	want := []pantherclawv1.InspectSection{
		pantherclawv1.InspectSection_INSPECT_SECTION_BUDGET, pantherclawv1.InspectSection_INSPECT_SECTION_GAPS,
		pantherclawv1.InspectSection_INSPECT_SECTION_LINEAGE,
	}
	if !slices.Equal(req.GetInclude(), want) || req.GetTimelinePageSize() != 500 || req.GetTimelinePageToken() != "tok" || req.GetRunId() != "r" {
		t.Errorf("request = %v", req)
	}
	if _, err := inspectRequest("r", []string{"transcript"}, 0, ""); err == nil {
		t.Error("an unknown section was accepted")
	}
	if _, ok := commands["run inspect"]; !ok {
		t.Error("run inspect is not registered")
	}
}

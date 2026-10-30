// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurancerpc

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/automations/assurance"
)

// TestPathsReachTheResponse: an inspection's paths and a replayed step's
// branch reach the response.
//
// Covers: F678
func TestPathsReachTheResponse(t *testing.T) {
	in := inspection(assurance.Inspection{Paths: []assurance.InspectedPath{{Nodes: []string{"a", "b"}, Outcome: "FAILED"}}})
	if len(in.GetPaths()) != 1 || !slices.Equal(in.GetPaths()[0].GetNodeIds(), []string{"a", "b"}) || in.GetPaths()[0].GetOutcome() != "FAILED" {
		t.Fatalf("paths %+v", in.GetPaths())
	}
	if s := simStep(assurance.SimStep{ID: "a", Branch: "route then"}); s.GetBranch() != "route then" || s.GetStepId() != "a" {
		t.Fatalf("step %+v", s)
	}
}

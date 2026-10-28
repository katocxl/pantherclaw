// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2aface

import (
	"encoding/json/v2"
	"maps"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestHR400_A2ARefusalCarriesOnlyTheAgentSafeExplanation: the A2A face's
// refusal adds the explanation with only its agent-safe keys.
//
// Covers: F330
func TestHR400_A2ARefusalCarriesOnlyTheAgentSafeExplanation(t *testing.T) {
	e := refusal(dispatch.Result{
		Class: dispatch.Held, Code: "APPROVAL_REQUIRED", Decision: pb.Decision_DECISION_REQUIRE_APPROVAL, TransactionID: "t-1",
		Explanation: &pb.AgentExplanation{
			Presentation: pb.DecisionPresentation_DECISION_PRESENTATION_HOLD, FailingCategory: "requirements",
			DecisiveCode: "APPROVAL_REQUIRED", TransactionId: "t-1",
			NextActions: []*pb.NextAction{{Code: "inspect_transaction", Label: "pclaw txn show t-1"}},
		},
	})
	b, err := json.Marshal(e.facts["explanation"])
	if err != nil {
		t.Fatal(err)
	}
	var x map[string]any
	if err := json.Unmarshal(b, &x); err != nil {
		t.Fatal(err)
	}
	want := []string{"decisive_code", "failing_category", "next_actions", "presentation", "transaction_id"}
	if keys := slices.Sorted(maps.Keys(x)); !slices.Equal(keys, want) || x["presentation"] != "hold" {
		t.Fatalf("explanation %s, want exactly %v", b, want)
	}
	if e := refusal(dispatch.Result{Class: dispatch.EnforcementFailed, Code: "circuit_open"}); e.facts["explanation"] != nil {
		t.Fatalf("a refusal without a decision has an explanation: %v", e.facts)
	}
}

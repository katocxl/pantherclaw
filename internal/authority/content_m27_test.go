// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
)

// TestHR400_AContentHoldTellsTheAgentNoKindOrLocation: an agent held by a
// content flag gets the code and the transaction, never what matched or
// where, which would teach it to get round the signal.
//
// Covers: F939
func TestHR400_AContentHoldTellsTheAgentNoKindOrLocation(t *testing.T) {
	res := Result{Decision: domain.RequireApproval, Checklist: []pipeline.Item{{
		Step: pipeline.StepRequirements, Check: "requirements", Status: pipeline.StatusFailed, Code: pipeline.ReasonContentFlagHold,
		Detail: "approval by approver is required: the outbound payload carries content flags (injection_phrase at arg/note)",
		Level:  pipeline.ContentLevel, Decisive: true,
	}}}
	x := agentExplanation("https://pc.example/", res, "0190f3b4-7c2e-7aaa-8bbb-0000000000aa")
	raw, err := protojson.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	if x.GetDecisiveCode() != pipeline.ReasonContentFlagHold {
		t.Fatalf("code %q", x.GetDecisiveCode())
	}
	for _, leak := range []string{"injection_phrase", "arg/note", "content flags", pipeline.ContentLevel} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("the agent saw %q: %s", leak, raw)
		}
	}
}

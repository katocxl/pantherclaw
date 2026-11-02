// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
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

// TestHR650_AnUnknownKindIsScanIncomplete: a kind outside the closed list, or
// a location that is not one, from a gateway becomes a scan_incomplete
// (unknown_kind) at the handler, never kept as sent; a known one stays. The
// scan marker maps one to one, and none is no marker (D533).
//
// Covers: F939
func TestHR650_AnUnknownKindIsScanIncomplete(t *testing.T) {
	got := contentOf([]*pantherclawv1.ContentFinding{
		{Kind: "made_up", Location: "arg/note"},
		{Kind: "injection_phrase", Location: "arg/note"},
		{Kind: "secret_format", Location: "has a space"},
	})
	want := []pipeline.PayloadFinding{
		{Kind: "scan_incomplete", Location: "unknown_kind"},
		{Kind: "injection_phrase", Location: "arg/note"},
		{Kind: "scan_incomplete", Location: "unknown_kind"},
	}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%d: %+v, want %+v", i, got[i], want[i])
		}
	}
	for in, out := range map[pantherclawv1.ContentScan]string{
		pantherclawv1.ContentScan_CONTENT_SCAN_UNSPECIFIED:      "",
		pantherclawv1.ContentScan_CONTENT_SCAN_SCANNED:          "SCANNED",
		pantherclawv1.ContentScan_CONTENT_SCAN_OFF:              "OFF",
		pantherclawv1.ContentScan_CONTENT_SCAN_FACE_NOT_SCANNED: "FACE_NOT_SCANNED",
		pantherclawv1.ContentScan(99):                           "",
	} {
		if got := scanOf(in); got != out {
			t.Errorf("%v: %q", in, got)
		}
	}
}

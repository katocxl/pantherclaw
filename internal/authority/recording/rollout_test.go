// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TestHR234_RecordingFromBeforeRolloutsReplaysIdentically: a recording made
// before per-agent policy selection (testdata, recorded by the code on main
// at 8fc4434a: format 1, pipeline 4) still decodes and encodes to the same
// bytes, and replays to the same decision, checklist and decision basis.
// The rollout fields are new and omitted when empty, so the format did not
// change (G0 M11.1, D12). The pipeline version did, for consequence chains
// (G0 M17 D133): this server still replays version 4, deciding as version
// 4 did, so the recording must replay exactly as it was decided.
func TestHR234_RecordingFromBeforeRolloutsReplaysIdentically(t *testing.T) {
	replaysIdentically(t, "recording_v1_hold", 4)
}

// TestHR234_RecordingOfThisVersionReplaysIdentically: a recording made by
// pipeline version 5 (testdata, the same hold recorded by this code)
// replays the same way.
func TestHR234_RecordingOfThisVersionReplaysIdentically(t *testing.T) {
	replaysIdentically(t, "recording_v5_hold", pipeline.Version)
}

// replaysIdentically checks the golden recording name, made by pipeline
// version v, under the policy bundle of recording_v1_hold.
func replaysIdentically(t *testing.T, name string, v int) {
	t.Helper()
	raw := readFixture(t, name+".json")
	rec, err := recording.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Format != recording.FormatVersion || rec.Pipeline != v || !pipeline.Replays(rec.Pipeline) {
		t.Fatalf("the fixture is format %d pipeline %d; want format %d pipeline %d, which pipeline %d replays: a version changed",
			rec.Format, rec.Pipeline, recording.FormatVersion, v, pipeline.Version)
	}
	if again, err := recording.Encode(rec); err != nil || !bytes.Equal(again, bytes.TrimSpace(raw)) {
		t.Fatalf("the fixture does not encode to the same bytes (%v)", err)
	}
	if p := rec.Reads.Policy; p == nil || p.Rollout != "" || p.Selected != "" {
		t.Fatalf("recorded policy = %+v, want one without a selection", p)
	}
	var b pdomain.Bundle
	if err := json.Unmarshal(readFixture(t, "recording_v1_hold.bundle.json"), &b); err != nil {
		t.Fatal(err)
	}
	s := pipelinetest.NewScenario(t, nil)
	served := recording.Served{Definitions: map[string]*defs.Definition{}, Consequences: map[string][]consequences.Rule{}}
	for _, d := range rec.Reads.Definitions {
		p, err := s.W.Definition(t.Context(), s.Org, d.Pin)
		if err != nil {
			t.Fatal(err)
		}
		served.Definitions[d.Digest], served.Consequences[d.Digest] = p.Definition, p.Consequences
	}
	if served.Policy, err = rec.Reads.Policy.Compile(&b); err != nil {
		t.Fatal(err)
	}
	rd := recording.NewReader(s.Org, rec, served)
	req, err := rd.Request()
	if err != nil {
		t.Fatal(err)
	}
	ev, err := (&pipeline.Pipeline{Replaying: rec.Pipeline}).EvaluateWith(t.Context(), rd, req)
	if err != nil || len(rd.Gaps()) > 0 {
		t.Fatalf("replay: %v, gaps %v", err, rd.Gaps())
	}
	if got, want := view(ev), string(readFixture(t, name+".view.txt")); got != want {
		t.Fatalf("the replay differs from the original:\noriginal %s\nreplayed %s", want, got)
	}
}

// TestHR234_RecordingKeepsThePolicySelection: an evaluation under a pilot's
// version records the rollout and the selection, and replays exactly.
func TestHR234_RecordingKeepsThePolicySelection(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	policy(t, s, pdomain.Rule{
		ID: "cap", Kind: pdomain.Forbid, Summary: "no refunds over 1000", Operations: []string{"payments.refund.create"},
		When: `action.params.amount > money("1000", "USD")`, Reason: "TOO_LARGE",
	})
	if err := s.W.SetAgentPolicy(s.Agent, []pdomain.Rule{holdOver50},
		map[string]fdomain.Type{"payments.charge.refundable": fdomain.TypeBoolean}); err != nil {
		t.Fatal(err)
	}
	req := refund(s, s.Run(g.ID, s.Alice), "ch_1", "70.00")
	rec := recording.NewRecorder(s.W, req)
	orig, err := (&pipeline.Pipeline{}).EvaluateWith(t.Context(), rec, req)
	if err != nil {
		t.Fatal(err)
	}
	if orig.Basis.Policy != "org-policy@2" || orig.Decisive().Code != "REFUND_OVER_50" {
		t.Fatalf("decided under %s with %s, want the pilot's org-policy@2 holding", orig.Basis.Policy, orig.Decisive().Code)
	}
	r, err := rec.Recording()
	if err != nil {
		t.Fatal(err)
	}
	if p := r.Reads.Policy; p.Rollout != "pilot" || p.Selected != pipeline.SelectedPilot || p.Ref != "org-policy@2" {
		t.Fatalf("recorded policy = %+v", p)
	}
	raw, err := recording.Encode(r)
	if err != nil || !strings.Contains(string(raw), `"selected":"PILOT"`) {
		t.Fatalf("encoded: %v %s", err, raw)
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

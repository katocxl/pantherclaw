// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TestM30_V8RecordingReplaysIdentically (G0 M30 D935a): a recording made at
// pipeline version 8, the version that reads the org's owned accounts,
// still decodes and encodes to the same bytes and replays to the same
// decision, checklist and basis. PC_GOLDEN=1 writes the fixture (once, by
// the code that introduced version 8).
func TestM30_V8RecordingReplaysIdentically(t *testing.T) {
	if os.Getenv("PC_GOLDEN") == "1" {
		writeV8Golden(t)
	}
	raw := readFixture(t, "recording_v8_hold.json")
	rec, err := recording.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Pipeline != 8 || !pipeline.Replays(rec.Pipeline) {
		t.Fatalf("the fixture is pipeline %d", rec.Pipeline)
	}
	if again, err := recording.Encode(rec); err != nil || !bytes.Equal(again, bytes.TrimSpace(raw)) {
		t.Fatalf("the fixture does not encode to the same bytes (%v)", err)
	}
	var b pdomain.Bundle
	if err := json.Unmarshal(readFixture(t, "recording_v8_hold.bundle.json"), &b); err != nil {
		t.Fatal(err)
	}
	ev := replayFixture(t, rec, &b)
	if got, want := view(ev), string(readFixture(t, "recording_v8_hold.view.txt")); got != want {
		t.Fatalf("the replay differs from the original:\noriginal %s\nreplayed %s", want, got)
	}
}

// writeV8Golden records a refund held at version 8 by the org's policy.
func writeV8Golden(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	policy(t, s, holdOver50)
	req := refund(s, s.Run(g.ID, s.Alice), "ch_1", "70.00")
	rec := recording.NewRecorder(s.W, req)
	ev, err := (&pipeline.Pipeline{}).EvaluateWith(t.Context(), rec, req)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rec.Recording()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := recording.Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := s.W.Policy(t.Context(), s.Org, s.Agent)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := json.Marshal(pol.Compiled.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"recording_v8_hold.json": raw, "recording_v8_hold.bundle.json": bundle, "recording_v8_hold.view.txt": []byte(view(ev))} {
		if err := os.WriteFile("testdata/"+name, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

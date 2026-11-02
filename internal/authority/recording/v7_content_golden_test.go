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

// TestM27_V7RecordingReplaysIdentically (G0 M27 D507): a recording made at
// pipeline version 7, whose decision read a content flag on the run, still
// decodes and encodes to the same bytes and replays to the same decision,
// checklist and basis. PC_GOLDEN=1 writes the fixture (once, by the code
// that introduced version 7).
// Covers: F939
func TestM27_V7RecordingReplaysIdentically(t *testing.T) {
	if os.Getenv("PC_GOLDEN") == "1" {
		writeV7Golden(t)
	}
	raw := readFixture(t, "recording_v7_content.json")
	rec, err := recording.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Pipeline != 7 || !pipeline.Replays(rec.Pipeline) {
		t.Fatalf("the fixture is pipeline %d", rec.Pipeline)
	}
	if again, err := recording.Encode(rec); err != nil || !bytes.Equal(again, bytes.TrimSpace(raw)) {
		t.Fatalf("the fixture does not encode to the same bytes (%v)", err)
	}
	var b pdomain.Bundle
	if err := json.Unmarshal(readFixture(t, "recording_v7_content.bundle.json"), &b); err != nil {
		t.Fatal(err)
	}
	ev := replayFixture(t, rec, &b)
	if got, want := view(ev), string(readFixture(t, "recording_v7_content.view.txt")); got != want {
		t.Fatalf("the replay differs from the original:\noriginal %s\nreplayed %s", want, got)
	}
	if ev.Decisive().Code != pipeline.ReasonContentFlagHold {
		t.Fatalf("decisive %s, want %s", ev.Decisive().Code, pipeline.ReasonContentFlagHold)
	}
}

// writeV7Golden records a refund held at version 7 by a content flag on its
// run, in ACTIVE.
func writeV7Golden(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	policy(t, s, holdOver50)
	s.W.SetContentSignals("ACTIVE", "injection_phrase")
	req := refund(s, s.Run(g.ID, s.Alice), "ch_1", "20.00")
	req.ContentScan = "SCANNED"
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
	for name, b := range map[string][]byte{"recording_v7_content.json": raw, "recording_v7_content.bundle.json": bundle, "recording_v7_content.view.txt": []byte(view(ev))} {
		if err := os.WriteFile("testdata/"+name, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

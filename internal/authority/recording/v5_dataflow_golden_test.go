// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Covers: F123

// TestHR431_AV5RecordingReplaysTheDataFlowHold (G0 M16 D95, D97): a
// recording made at pipeline version 5, whose refund through a public
// connection followed a pii read in its run tree, carries the recorded
// sensitive reads, decodes and encodes to the same bytes, and replays to
// the same DATA_FLOW_HOLD, checklist and basis. PC_GOLDEN=1 writes the
// fixture.
func TestHR431_AV5RecordingReplaysTheDataFlowHold(t *testing.T) {
	if os.Getenv("PC_GOLDEN") == "1" {
		writeV5DataFlowGolden(t)
	}
	raw := readFixture(t, "recording_v5_dataflow.json")
	rec, err := recording.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Pipeline != 5 || rec.Reads.Sensitive == nil || len(rec.Reads.Sensitive.Reads) != 1 || rec.Reads.Sensitive.Reads[0].Class != "pii" {
		t.Fatalf("the fixture is pipeline %d with sensitive reads %+v", rec.Pipeline, rec.Reads.Sensitive)
	}
	if again, err := recording.Encode(rec); err != nil || !bytes.Equal(again, bytes.TrimSpace(raw)) {
		t.Fatalf("the fixture does not encode to the same bytes (%v)", err)
	}
	var b pdomain.Bundle
	if err := json.Unmarshal(readFixture(t, "recording_v5_dataflow.bundle.json"), &b); err != nil {
		t.Fatal(err)
	}
	ev := replayFixture(t, rec, &b)
	if got, want := view(ev), string(readFixture(t, "recording_v5_dataflow.view.txt")); got != want {
		t.Fatalf("the replay differs from the original:\noriginal %s\nreplayed %s", want, got)
	}
	if ev.Decisive().Code != pipeline.ReasonDataFlowHold {
		t.Fatalf("decisive %s, want %s", ev.Decisive().Code, pipeline.ReasonDataFlowHold)
	}
}

// writeV5DataFlowGolden records a held refund at version 5: the run read
// pii data earlier, and the refund goes out through a public connection.
func writeV5DataFlowGolden(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	policy(t, s, holdOver50)
	run := s.Run(g.ID, s.Alice)
	c, err := s.W.Connection(context.Background(), s.Org, s.Connection)
	if err != nil {
		t.Fatal(err)
	}
	c.DestinationClass = "public"
	s.W.PutConnection(c)
	s.W.AddSensitiveRead(pipeline.SensitiveRead{
		TransactionID: ids.NewV7(), RunID: run, Operation: "payments.refund.get", Class: "pii", At: s.W.Cont.Now.Add(-time.Minute),
	})
	req := refund(s, run, "ch_1", "20.00")
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
	for name, b := range map[string][]byte{
		"recording_v5_dataflow.json": raw, "recording_v5_dataflow.bundle.json": bundle, "recording_v5_dataflow.view.txt": []byte(view(ev)),
	} {
		if err := os.WriteFile("testdata/"+name, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

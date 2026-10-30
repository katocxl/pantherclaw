// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// heldAtRisk holds refunds while the person behind the run has an open
// identity-risk signal (`principal.risk`, G0 M16 D82).
var heldAtRisk = pdomain.Rule{
	ID: "risk", Kind: pdomain.RequireApproval, Summary: "refunds at risk need approval", Operations: []string{"payments.refund.create"},
	When: `principal.risk.open`, Reason: "IDENTITY_RISK", Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
}

// TestM16_V5RecordingReplaysIdentically (G0 M16 D95): a recording made at
// pipeline version 5, whose decision read an identity-risk fact, still
// decodes and encodes to the same bytes and replays to the same decision,
// checklist and basis. PC_GOLDEN=1 writes the fixture (once, by the code
// that introduced version 5).
// Covers: F366
func TestM16_V5RecordingReplaysIdentically(t *testing.T) {
	if os.Getenv("PC_GOLDEN") == "1" {
		writeV5Golden(t)
	}
	raw := readFixture(t, "recording_v5_risk.json")
	rec, err := recording.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Pipeline != 5 || !pipeline.Replays(rec.Pipeline) {
		t.Fatalf("the fixture is pipeline %d", rec.Pipeline)
	}
	if again, err := recording.Encode(rec); err != nil || !bytes.Equal(again, bytes.TrimSpace(raw)) {
		t.Fatalf("the fixture does not encode to the same bytes (%v)", err)
	}
	var b pdomain.Bundle
	if err := json.Unmarshal(readFixture(t, "recording_v5_risk.bundle.json"), &b); err != nil {
		t.Fatal(err)
	}
	ev := replayFixture(t, rec, &b)
	if got, want := view(ev), string(readFixture(t, "recording_v5_risk.view.txt")); got != want {
		t.Fatalf("the replay differs from the original:\noriginal %s\nreplayed %s", want, got)
	}
	if ev.Decisive().Code != "IDENTITY_RISK" {
		t.Fatalf("decisive %s, want IDENTITY_RISK", ev.Decisive().Code)
	}
}

func replayFixture(t *testing.T, rec *recording.Recording, b *pdomain.Bundle) *pipeline.Evaluation {
	t.Helper()
	s := pipelinetest.NewScenario(t, nil)
	served := recording.Served{Definitions: map[string]*defs.Definition{}, Consequences: map[string][]consequences.Rule{}}
	for _, d := range rec.Reads.Definitions {
		p, err := s.W.Definition(t.Context(), s.Org, d.Pin)
		if err != nil {
			t.Fatal(err)
		}
		served.Definitions[d.Digest], served.Consequences[d.Digest] = p.Definition, p.Consequences
	}
	var err error
	if served.Policy, err = rec.Reads.Policy.Compile(b); err != nil {
		t.Fatal(err)
	}
	rd := recording.NewReader(s.Org, rec, served)
	req, err := rd.Request()
	if err != nil {
		t.Fatal(err)
	}
	ev, err := (&pipeline.Pipeline{ReplayOf: rec.Pipeline}).EvaluateWith(t.Context(), rd, req)
	if err != nil || len(rd.Gaps()) > 0 {
		t.Fatalf("replay: %v, gaps %v", err, rd.Gaps())
	}
	return ev
}

// writeV5Golden records a held refund at version 5: the launcher has an
// open identity-risk signal and the policy holds refunds at risk.
func writeV5Golden(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	policy(t, s, heldAtRisk)
	s.W.PutFact(fdomain.Fact{
		Name: fdomain.NameIdentityRisk, SubjectType: fdomain.SubjectUser, SubjectID: s.Alice.ID.String(),
		ObservedAt: s.W.Cont.Now.Add(-time.Hour), RecordedAt: s.W.Cont.Now.Add(-time.Hour), ProviderID: ids.NewV7(),
		Value: fdomain.Value{Type: fdomain.TypeObject, Object: map[string]any{"event": "credential-change", "level": "high", "at": s.W.Cont.Now.Add(-time.Hour).Unix()}},
	})
	req := refund(s, s.Run(g.ID, s.Alice), "ch_1", "20.00")
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
	for name, b := range map[string][]byte{"recording_v5_risk.json": raw, "recording_v5_risk.bundle.json": bundle, "recording_v5_risk.view.txt": []byte(view(ev))} {
		if err := os.WriteFile("testdata/"+name, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

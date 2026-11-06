// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording_test

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"os"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	pcbrowser "github.com/katocxl/pantherclaw/packages/pc-browser"
)

func browserScenario(t *testing.T) *pipelinetest.Scenario {
	t.Helper()
	return pipelinetest.NewScenario(t, func(string) string { return string(pcbrowser.Package) })
}

// TestM33_V9RecordingReplaysIdentically records an unlisted-site hold and
// checks that replay preserves its decision, checklist and basis (D1220).
func TestM33_V9RecordingReplaysIdentically(t *testing.T) {
	if os.Getenv("PC_GOLDEN") == "1" {
		writeV9Golden(t)
	}
	raw := readFixture(t, "recording_v9_browser.json")
	rec, err := recording.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Pipeline != 9 || !pipeline.Replays(rec.Pipeline) {
		t.Fatalf("pipeline %d, want replayable 9", rec.Pipeline)
	}
	if again, err := recording.Encode(rec); err != nil || !bytes.Equal(again, bytes.TrimSpace(raw)) {
		t.Fatalf("encode: %v", err)
	}
	var b pdomain.Bundle
	if err := json.Unmarshal(readFixture(t, "recording_v9_browser.bundle.json"), &b); err != nil {
		t.Fatal(err)
	}
	s := browserScenario(t)
	served := recording.Served{Definitions: map[string]*defs.Definition{}, Consequences: map[string][]consequences.Rule{}}
	for _, d := range rec.Reads.Definitions {
		p, err := s.W.Definition(t.Context(), s.Org, d.Pin)
		if err != nil {
			t.Fatal(err)
		}
		served.Definitions[d.Digest], served.Consequences[d.Digest] = p.Definition, p.Consequences
	}
	served.Policy, err = rec.Reads.Policy.Compile(&b)
	if err != nil {
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
	if ev.Decisive().Code != pipeline.ReasonSiteNotListed {
		t.Fatalf("decisive %s", ev.Decisive().Code)
	}
	if got, want := view(ev), string(readFixture(t, "recording_v9_browser.view.txt")); got != want {
		t.Fatalf("replay differs:\n%s\n%s", want, got)
	}
}

func writeV9Golden(t *testing.T) {
	s := browserScenario(t)
	gw, err := ids.ParseUUID(s.Gateway.ID)
	if err != nil {
		t.Fatal(err)
	}
	s.W.PutConnection(pipeline.Connection{ID: s.Connection, Gateway: gw, Kind: "local", Package: "pc.browser", State: "ACTIVE", AccessMode: "none", DefaultMode: pipeline.ModeEnforce, Modes: map[string]string{}})
	g := s.Grant(`{"operations":["browser.navigate"],"targets":{"browser.site":{"prefixes":["e"]}}}`, s.Alice)
	policy(t, s, pdomain.Rule{ID: "never", Kind: pdomain.Forbid, Summary: "no matching policy", Operations: []string{"browser.navigate"}, When: "false", Reason: "NEVER"})
	run := s.Run(g.ID, s.Alice)
	action, err := s.Mapper.Hook(t.Context(), mapping.Context{Org: s.Org.String(), Env: s.Env.String(), RunID: run.String(), ActionID: ids.NewV7().String(), AgentInstance: s.Instance.String(), Connection: s.Connection.String()}, "browser_navigate", jsontext.Value(`{"url":"https://example.com/","call":"c1"}`))
	if err != nil {
		t.Fatal(err)
	}
	req := pipeline.Request{Org: s.Org, Action: action, Identity: pipeline.Identity{InstanceID: s.Instance, AgentID: s.Agent, AttestationLevel: 1, JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}, Gateway: s.Gateway.ID}
	rec := recording.NewRecorder(s.W, req)
	ev, err := (&pipeline.Pipeline{}).EvaluateWith(t.Context(), rec, req)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Decisive().Code != pipeline.ReasonSiteNotListed {
		t.Fatalf("decisive %s, want %s", ev.Decisive().Code, pipeline.ReasonSiteNotListed)
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
	for name, b := range map[string][]byte{"recording_v9_browser.json": raw, "recording_v9_browser.bundle.json": bundle, "recording_v9_browser.view.txt": []byte(view(ev))} {
		if err := os.WriteFile("testdata/"+name, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

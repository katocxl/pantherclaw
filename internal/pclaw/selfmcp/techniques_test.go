// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package selfmcp

import (
	"encoding/json/v2"
	"strings"
	"testing"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	tmdomain "github.com/katocxl/pantherclaw/internal/threatmap/domain"
)

// TestF947_TechniqueCoverageReachesGetThreatTechnique: the tool's arguments
// arrive as the read's request, the framework from the id when not given,
// and the result carries the map's statement (G0 M28 D726, D717).
// Covers: F947, HR-681
func TestF947_TechniqueCoverageReachesGetThreatTechnique(t *testing.T) {
	agent := uuid()
	for _, c := range []struct {
		args map[string]any
		want pb.ThreatFramework
	}{
		{map[string]any{"technique_id": "T1552.001", "agent_id": agent}, pb.ThreatFramework_THREAT_FRAMEWORK_ATTACK_ENTERPRISE},
		{map[string]any{"technique_id": "T1078", "framework": "attack-enterprise"}, pb.ThreatFramework_THREAT_FRAMEWORK_ATTACK_ENTERPRISE},
		{map[string]any{"technique_id": "AML.T0051.000", "framework": "atlas"}, pb.ThreatFramework_THREAT_FRAMEWORK_ATLAS},
		{map[string]any{"technique_id": "AML.T0053"}, pb.ThreatFramework_THREAT_FRAMEWORK_ATLAS},
	} {
		f := &fakeBackend{technique: &pb.GetThreatTechniqueResponse{}}
		as, raw := serve(t, f, callLine(t, "technique_coverage", c.args))
		if as[0].Error != nil || as[0].Result.IsError {
			t.Fatalf("%v: %s", c.args, raw)
		}
		q := f.lastTech
		if q.GetTechniqueId() != c.args["technique_id"] || q.GetFramework() != c.want {
			t.Errorf("%v: request %v", c.args, q)
		}
		if a, _ := c.args["agent_id"].(string); q.GetAgentId() != a || q.GetEnvironmentId() != "" {
			t.Errorf("%v: scope %v", c.args, q)
		}
		// The statement is in the record, once per copy.
		var env struct {
			Record struct {
				Statement string `json:"statement"`
			} `json:"record"`
		}
		if err := json.Unmarshal([]byte(as[0].Result.Content[0].Text), &env); err != nil || env.Record.Statement != tmdomain.Statement {
			t.Errorf("%v: statement %q (%v)", c.args, env.Record.Statement, err)
		}
	}
}

// TestHR681_SelfMCPTextUsesNoBannedWord: the server's instructions and every
// tool's name, title, description and schema text pass the threat map's
// wording rule, the statement removed first (G0 M28 D717, D717a).
// Covers: HR-681, F947
func TestHR681_SelfMCPTextUsesNoBannedWord(t *testing.T) {
	texts := map[string]string{"instructions": instructions, "notice": untrustedNotice}
	for _, x := range tools {
		b, err := json.Marshal(x.Schema)
		if err != nil {
			t.Fatal(err)
		}
		texts[x.Name] = strings.Join([]string{x.Name, x.Title, x.Description, string(b)}, "\n")
	}
	for name, s := range texts {
		if w := tmdomain.BannedWord(s); w != "" {
			t.Errorf("%s uses %q", name, w)
		}
	}
	// A result keeps the statement word for word and adds no banned word.
	f := &fakeBackend{technique: &pb.GetThreatTechniqueResponse{Statement: tmdomain.Statement}}
	_, raw := serve(t, f, callLine(t, "technique_coverage", map[string]any{"technique_id": "T1078"}))
	if !strings.Contains(raw, tmdomain.Statement) {
		t.Errorf("the statement is not verbatim: %.300s", raw)
	}
	if w := tmdomain.BannedWord(raw); w != "" {
		t.Errorf("the result uses %q", w)
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pack

import (
	"context"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

const runtimeDeployed = "pc.runtime.agent_deployed"

func TestRuntimeDetectionMatchesTheRecordedAudit(t *testing.T) {
	event, err := feed.Normalize("audit.agent.discovered", "gateway", "gateway-1", time.Now(), []byte(`{"details":{"discovery_id":"01a1b2fb-d89f-730e-8c06-12a3ab8340cf","source":"aws_agentcore"},"name":"agent.discovered","object":{"id":"01a1b2fb-d89d-73bb-a7d9-864d58248943","type":"agent"},"outcome":"success"}`))
	if err != nil {
		t.Fatal(err)
	}
	event.Org = ids.New[ids.Org]()
	event.ID = ids.NewV7()
	p, err := Load(env(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range p.Rules {
		if c.Rule.ID == runtimeDeployed {
			result, err := engine.Evaluate(context.Background(), engine.NewMemory(), c, event)
			if err != nil || result.Fired == nil {
				t.Fatalf("recorded audit did not match: %+v, %v; event %+v", result, err, event)
			}
			if err := engine.Signal(c, event, *result.Fired).Validate(); err != nil {
				t.Fatalf("matched audit produced an invalid alert: %v", err)
			}
			return
		}
	}
	t.Fatal("runtime rule missing")
}

// TestHR769_TheDeployedAgentDetectionAlertsOnly: pc.runtime.agent_deployed
// is attention ALERT (never an incident or a page), LOW, mapped to
// AML.T0103, on audit.agent.discovered only, and no other built-in file
// names it, so no built-in response holds or contains on it.
func TestHR769_TheDeployedAgentDetectionAlertsOnly(t *testing.T) {
	p, err := Load(env(t))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range p.Rules {
		r := c.Rule
		if r.ID != runtimeDeployed {
			continue
		}
		found = true
		if r.Attention != reflexdomain.AttentionAlert || r.Severity != reflexdomain.SeverityLow ||
			!slices.Equal(r.On, []string{"audit.agent.discovered"}) || !slices.Equal(r.ATLAS, []string{"AML.T0103"}) ||
			!strings.Contains(r.Description, "An alert only") {
			t.Fatalf("rule %+v", r)
		}
	}
	if !found {
		t.Fatalf("%s is not in the pack", runtimeDeployed)
	}
	err = fs.WalkDir(builtin, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path == "builtin/runtime_agent_deployed.yaml" || strings.HasSuffix(path, "manifest.json") {
			return err
		}
		b, err := fs.ReadFile(builtin, path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), runtimeDeployed) {
			t.Errorf("%s names %s", path, runtimeDeployed)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestHR769_ItAlertsOnANewAgentFromTheThreeRuntimes: a discovery from
// AgentCore, Vertex AI Agent Engine or Azure AI Foundry fires it; one from
// another source, or another kind of audit event from a runtime source,
// does not.
func TestHR769_ItAlertsOnANewAgentFromTheThreeRuntimes(t *testing.T) {
	ev := func(kind, source string) rules.TestEvent {
		return rules.TestEvent{
			Kind: kind, ActorType: "user", ActorID: "01930000-0000-7000-8000-0000000000u1", Outcome: "success",
			Subjects: map[string]string{"agent": "01930000-0000-7000-8000-0000000000a1"},
			Attrs:    map[string]string{"object_type": "agent", "discovery_id": "01930000-0000-7000-8000-0000000000d1", "source": source},
		}
	}
	for _, s := range []string{"aws_agentcore", "vertex_agent_engine", "azure_foundry"} {
		if !fires(t, runtimeDeployed, ev("audit.agent.discovered", s)) {
			t.Errorf("%s did not fire", s)
		}
	}
	for name, e := range map[string]rules.TestEvent{
		"copilot studio": ev("audit.agent.discovered", "copilot_studio"),
		"local scan":     ev("audit.agent.discovered", "local"),
		"no source":      ev("audit.agent.discovered", ""),
		"dismissed":      ev("audit.agent.discovery_dismissed", "aws_agentcore"),
	} {
		if fires(t, runtimeDeployed, e) {
			t.Errorf("%s fired", name)
		}
	}
}

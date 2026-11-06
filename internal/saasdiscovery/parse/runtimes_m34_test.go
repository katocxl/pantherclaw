// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package parse

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
)

// closedAttrs are the only attributes a runtime finding may carry (D997).
var closedAttrs = []string{"tenant", "agent_id", "name", "region", "location", "status", "created_at", "updated_at"}

func checkClosed(t *testing.T, f domain.Finding) {
	t.Helper()
	for k, v := range f.Attributes {
		if !slices.Contains(closedAttrs, k) {
			t.Errorf("%s: attribute %s=%q is outside the closed set", f.Kind, k, v)
		}
		if strings.Contains(v, "secret-env") || strings.Contains(v, "arn:aws:iam") {
			t.Errorf("%s: %s carries %q", f.Kind, k, v)
		}
	}
}

// TestD997_RuntimeRecordingsKeepTheClosedAttributesOnly: an AgentCore,
// Vertex or Foundry recording becomes one finding per agent with only the
// closed attributes (never a role, environment, container or
// instructions); a record with no usable id, a Vertex engine of another
// project, a recording with more pages, a wrong tenant and a wrong shape
// are refused or noted, never read as an empty result.
func TestD997_RuntimeRecordingsKeepTheClosedAttributesOnly(t *testing.T) {
	agentcore := `{"account_id":"111122223333","region":"us-east-1","runtimes":{"agentRuntimes":[
	  {"agentRuntimeId":"support_agent-AbC123","agentRuntimeName":"support","status":"READY","createdAt":1762300000,"lastUpdatedAt":"2026-11-05T10:00:00Z",
	   "roleArn":"arn:aws:iam::111122223333:role/x","environmentVariables":{"K":"secret-env"}},
	  {"agentRuntimeId":"bad id with spaces","agentRuntimeName":"x"}]}}`
	r, err := Recording(domain.SourceAWSAgentCore, []byte(agentcore))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Counts[domain.CountAgents] != 1 || r.Findings[0].Kind != domain.KindAgentCoreRuntime {
		t.Fatalf("agentcore findings %+v", r.Findings)
	}
	f := r.Findings[0]
	checkClosed(t, f)
	if f.Attributes["status"] != "ready" || f.Attributes["region"] != "us-east-1" || f.Attributes["created_at"] != "2025-11-04T23:46:40Z" ||
		f.Attributes["tenant"] != "111122223333" {
		t.Errorf("agentcore attributes %v", f.Attributes)
	}
	if !slices.Contains(r.Scanned, domain.ReadRuntimes) {
		t.Errorf("runtimes not read: %+v", r)
	}

	vertex := `{"project":"acme-agents","location":"us-central1","reasoning_engines":{"reasoningEngines":[
	  {"name":"projects/acme-agents/locations/us-central1/reasoningEngines/123456","displayName":"triage","state":"ACTIVE","createTime":"2026-11-01T00:00:00Z",
	   "spec":{"packageSpec":{"pickleObjectGcsUri":"gs://secret-env"}}},
	  {"name":"projects/other-proj/locations/us-central1/reasoningEngines/999","displayName":"elsewhere"}]}}`
	r, err = Recording(domain.SourceVertexAgentEngine, []byte(vertex))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Attributes["agent_id"] != "123456" || r.Findings[0].Attributes["location"] != "us-central1" {
		t.Fatalf("vertex findings %+v", r.Findings)
	}
	checkClosed(t, r.Findings[0])

	foundry := `{"project":"support","agents":{"data":[{"id":"asst_abc123","name":"helper","created_at":1762300000,"instructions":"secret-env"}],"has_more":true,"last_id":"asst_abc123"}}`
	r, err = Recording(domain.SourceAzureFoundry, []byte(foundry))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || slices.Contains(r.Scanned, domain.ReadAgents) || r.NotScanned[domain.ReadAgents] == "" {
		t.Fatalf("foundry with more pages: %+v", r)
	}
	checkClosed(t, r.Findings[0])

	for name, tc := range map[string]struct {
		source, raw string
		want        error
	}{
		"agentcore no list":   {domain.SourceAWSAgentCore, `{"account_id":"111122223333","region":"us-east-1"}`, ErrShape},
		"agentcore tenant":    {domain.SourceAWSAgentCore, `{"account_id":"1111","region":"us-east-1","runtimes":{"agentRuntimes":[]}}`, ErrTenant},
		"vertex tenant":       {domain.SourceVertexAgentEngine, `{"project":"A","location":"us-central1","reasoning_engines":{}}`, ErrTenant},
		"foundry no data":     {domain.SourceAzureFoundry, `{"project":"support","agents":{}}`, ErrShape},
		"foundry not JSON":    {domain.SourceAzureFoundry, `[`, ErrShape},
		"agentcore not JSONs": {domain.SourceAWSAgentCore, `"x"`, ErrShape},
	} {
		_, err := Recording(tc.source, []byte(tc.raw))
		if tc.want == nil {
			continue
		}
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if _, _, err := FoundryPage([]byte(`{"data":[],"has_more":true}`)); !errors.Is(err, ErrShape) {
		t.Errorf("a Foundry page with more and no cursor: %v", err)
	}
	if got, next, err := VertexPage([]byte(`{}`)); err != nil || got != nil || next != "" {
		t.Errorf("an empty Vertex page: %v %q %v", got, next, err)
	}
	if _, _, err := AgentCorePage([]byte(`{}`)); !errors.Is(err, ErrShape) {
		t.Errorf("an AgentCore page with no list: %v", err)
	}
}

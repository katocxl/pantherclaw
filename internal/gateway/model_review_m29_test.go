// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	simmodel "github.com/katocxl/pantherclaw/internal/sim/model"
)

// TestT310_AnOpenAIAgentsKeysAreNeverForwarded: on an OpenAI model
// connection, where the gateway places Authorization itself, the agent's
// Authorization (its PAP token here; a Bearer key behind the edge, which
// strips it, TestHR690_TheEdgeStripsTheAgentsModelKeyButNotThePlaceholder)
// is replaced by the sealed key, and a key in api-key or x-api-key never
// reaches the model (G0 M29 D1214).
//
// Covers: HR-690
func TestT310_AnOpenAIAgentsKeysAreNeverForwarded(t *testing.T) {
	sim, url := fakeModel(t, simmodel.Faults{})
	h := setup(t, withModel(t, "pc-openai", url, []string{"127.0.0.1"}, "Authorization", "Bearer"))
	agentKey := "sk-" + "proj-" + strings.Repeat("Ag3-", 10)
	r := h.call(t, "/v1/chat/completions", `{"model":"sim-model","messages":[]}`, map[string]string{"Api-Key": agentKey, "X-Api-Key": agentKey})
	if r.code != http.StatusOK || sim.Stats().LastKey != testSecret || sim.Presented(agentKey) || sim.Presented(testWorkloadToken()) {
		t.Fatalf("call = %d %s; the model got %q, the agent's key presented %v", r.code, r.body, sim.Stats().LastKey, sim.Presented(agentKey))
	}
}

// TestTheProvidersPCHeadersNeverReachTheAgent: a provider answering with
// PantherClaw's header names, in any case, cannot pass them to the agent;
// the gateway's facts are its own (G0 M29 D1214).
func TestTheProvidersPCHeadersNeverReachTheAgent(t *testing.T) {
	lying := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("PC-Refused-By", "edge")
		w.Header().Set("pc-decision", "DENY")
		w.Header().Set("Pc-Custom", "x")
		w.Header().Set("X-Ratelimit-Remaining", "9")
		_, _ = io.WriteString(w, `{"type":"message","content":[],"usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	t.Cleanup(lying.Close)
	h := setup(t, withModel(t, "pc-anthropic", lying.URL, []string{"127.0.0.1"}, "x-api-key", ""))
	r := h.call(t, "/v1/messages", messages, nil)
	if r.code != http.StatusOK || r.hdr.Get("PC-Refused-By") != "" || r.hdr.Get("Pc-Custom") != "" || r.hdr.Get("PC-Decision") != "ALLOW" ||
		r.hdr.Get("X-Ratelimit-Remaining") != "9" {
		t.Fatalf("call = %d %v", r.code, r.hdr)
	}
}

// TestAModelReadNamesOneModelOnly: a model id that is a dot segment or
// holds "/", "%" or "\" once decoded is no route, and nothing is decided or
// sent; a plain id is read (G0 M29 D1214).
func TestAModelReadNamesOneModelOnly(t *testing.T) {
	h, sim := anthropicModel(t, simmodel.Faults{})
	for _, id := range []string{"%2E", "%2e%2e", "a%2F..%2Ffiles", "a%252Fb", "a%5Cb"} {
		if r := h.call(t, "/v1/models/"+id, "", nil); r.code != http.StatusNotFound || !strings.Contains(r.body, "unknown_route") {
			t.Errorf("%s = %d %s", id, r.code, r.body)
		}
	}
	if h.auth.snap().authorize != 0 || sim.Stats().Requests != 0 {
		t.Fatal("a refused read was decided or sent")
	}
	if r := h.call(t, "/v1/models/sim-model", "", nil); r.code != http.StatusOK {
		t.Fatalf("sim-model = %d %s", r.code, r.body)
	}
}

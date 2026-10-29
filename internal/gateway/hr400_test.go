// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"encoding/json/v2"
	"maps"
	"slices"
	"strings"
	"testing"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// explanationKeys are the only keys of a refusal's explanation (HR-400),
// and actionKeys the only keys of each recovery action.
var (
	explanationKeys = []string{"decisive_code", "failing_category", "next_actions", "presentation", "transaction_id"}
	actionKeys      = []string{"code", "label", "url"}
)

// checkExplanation asserts the explanation in a refusal body has exactly
// the agent-safe keys, the decision's presentation and code, and none of
// the decision's detail (the grant's limit).
func checkExplanation(t *testing.T, name string, raw []byte, txn string) {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	x, ok := body["explanation"].(map[string]any)
	if !ok {
		t.Fatalf("%s: no explanation in %s", name, raw)
	}
	if keys := slices.Sorted(maps.Keys(x)); !slices.Equal(keys, explanationKeys) {
		t.Fatalf("%s: explanation keys %v, want exactly %v", name, keys, explanationKeys)
	}
	acts, _ := x["next_actions"].([]any)
	if len(acts) != 1 {
		t.Fatalf("%s: next_actions %v", name, x["next_actions"])
	}
	a, _ := acts[0].(map[string]any)
	if keys := slices.Sorted(maps.Keys(a)); !slices.Equal(keys, actionKeys) {
		t.Fatalf("%s: action keys %v, want exactly %v", name, keys, actionKeys)
	}
	if x["presentation"] != "deny" || x["failing_category"] != "authority" || x["decisive_code"] != "GRANT_AMOUNT_EXCEEDED" ||
		x["transaction_id"] != txn || a["label"] != "pclaw txn show "+txn {
		t.Fatalf("%s: explanation %v", name, x)
	}
	if b, _ := json.Marshal(x); strings.Contains(string(b), "10.00") || strings.Contains(string(b), "30.00") {
		t.Fatalf("%s: the explanation carries a limit or request value: %s", name, b)
	}
}

// TestHR400_RefusalsCarryOnlyTheAgentSafeExplanation: a refusal from the
// HTTP proxy and from the hook face adds only the agent-safe explanation
// (presentation, failing category, decisive code, transaction id and
// recovery actions), never the decision's detail, grant or limits.
//
// Covers: F330
func TestHR400_RefusalsCarryOnlyTheAgentSafeExplanation(t *testing.T) {
	deny := func(h *harness) { h.auth.decision = pb.Decision_DECISION_DENY }

	h := setup(t, deny)
	r := h.post(t, inbound, nil)
	if r.refusal.Decision == "" || h.target.calls() != 0 {
		t.Fatalf("refusal = %d %s", r.code, r.body)
	}
	checkExplanation(t, "http proxy", []byte(r.body), h.auth.snap().txn)

	h = setup(t, withShell, deny)
	hr := h.hook(t, shellInput("rm -rf build", "/home/dev/proj"), nil)
	if hr.answer.Decision != "deny" {
		t.Fatalf("hook = %+v", hr.answer)
	}
	checkExplanation(t, "hook", hr.raw, h.auth.snap().txn)
}

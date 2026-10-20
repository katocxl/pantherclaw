// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// scopedRefundRead declares the refund read's status pii and lets it
// enforce data classes (D9, D20).
func scopedRefundRead(raw []byte) []byte {
	anchor := "      valid_until: 2027-10-08\n    mappings:\n      - channel: http\n        method: GET\n        path: /v1/refunds/{refund}\n"
	return []byte(strings.Replace(string(raw), anchor,
		"      valid_until: 2027-10-08\n    response:\n      format: json\n      fields:\n        - {path: status, class: pii}\n    scoping: [classes]\n"+
			anchor[len("      valid_until: 2027-10-08\n"):], 1))
}

func classesOnly(values ...string) []*pb.Obligation {
	return []*pb.Obligation{{Kind: "data_classes", Values: values, Timing: "before_execution"}}
}

// TestHR311_JSONAnswerRedactedThroughTheGateway (D20): under a data_classes
// obligation the agent gets the answer with the values of the classes it
// may not read withheld, on the HTTP face and the MCP face alike; without
// one, the answer passes unchanged.
func TestHR311_JSONAnswerRedactedThroughTheGateway(t *testing.T) {
	h := setup(t, withCredential(t, []string{"127.0.0.1"}), func(h *harness) { h.mutatePkg = scopedRefundRead })
	r := h.do(t, http.MethodGet, "/payments/v1/refunds/re_1", "", nil)
	if r.code != http.StatusOK || !strings.Contains(r.body, `"status":"succeeded"`) {
		t.Fatalf("unscoped: %d %s", r.code, r.body)
	}
	h.auth.mu.Lock()
	h.auth.obligations = classesOnly("public")
	h.auth.mu.Unlock()
	r = h.do(t, http.MethodGet, "/payments/v1/refunds/re_1", "", nil)
	if r.code != http.StatusOK || !strings.Contains(r.body, `"status":"[redacted:pii]"`) || strings.Contains(r.body, "succeeded") ||
		!strings.Contains(r.body, `"id":"re_1"`) {
		t.Fatalf("scoped http: %d %s", r.code, r.body)
	}
	recs := h.auth.snap().records
	if ds := recs[len(recs)-1].GetDataScope(); ds.GetRows() != 1 || ds.GetValuesRedacted() != 1 {
		t.Fatalf("data scope on the record: %v", ds)
	}
	m := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", `"name":"get_refund","arguments":{"refund":"re_1"}`), nil)
	if m.body.Result.IsError || !strings.Contains(string(m.body.Result.StructuredContent), `"status":"[redacted:pii]"`) {
		t.Fatalf("scoped mcp: %+v", m.body.Result)
	}
	h.auth.mu.Lock()
	h.auth.obligations = classesOnly("public", "pii")
	h.auth.mu.Unlock()
	if r := h.do(t, http.MethodGet, "/payments/v1/refunds/re_1", "", nil); !strings.Contains(r.body, `"status":"succeeded"`) {
		t.Fatalf("pii allowed: %s", r.body)
	}
}

// TestT144_UnreadableAnswerIsWithheld (D20): an answer the scope engine
// cannot read is withheld from the agent, SCOPE_UNENFORCEABLE, while the
// call's outcome is still recorded.
func TestT144_UnreadableAnswerIsWithheld(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html>Ada Lovelace, ada@example.com</html>")
	}))
	t.Cleanup(ts.Close)
	h := setup(t, withCredential(t, []string{"127.0.0.1"}), func(h *harness) { h.mutatePkg, h.targetURL = scopedRefundRead, ts.URL })
	h.auth.mu.Lock()
	h.auth.obligations = classesOnly("public")
	h.auth.mu.Unlock()
	r := h.do(t, http.MethodGet, "/payments/v1/refunds/re_1", "", nil)
	if r.refusal.Error != "scope_unenforceable" || strings.Contains(r.body, "Ada") || len(h.auth.snap().records) != 1 {
		t.Fatalf("%d %s, %d recorded", r.code, r.body, len(h.auth.snap().records))
	}
}

// TestT144_ScopeTheRouteCannotEnforceSendsNothing (HR-302): a record scope
// on an http connection, or a data_classes scope on a definition that does
// not declare it, is refused before anything reaches the target.
func TestT144_ScopeTheRouteCannotEnforceSendsNothing(t *testing.T) {
	for name, opt := range map[string]func(*harness){
		"records on http": func(h *harness) {
			h.mutatePkg = scopedRefundRead
			h.auth.obligations = []*pb.Obligation{{Kind: "record_scope", Param: "customer", Values: []string{"1"}, Timing: "before_execution"}}
		},
		"classes undeclared": func(h *harness) { h.auth.obligations = classesOnly("public") },
	} {
		h := setup(t, opt)
		r := h.do(t, http.MethodGet, "/payments/v1/refunds/re_1", "", nil)
		if r.refusal.Error != "scope_unsupported" || h.target.calls() != 0 || len(h.auth.snap().begins) != 0 {
			t.Errorf("%s: %d %s, target %d", name, r.code, r.body, h.target.calls())
		}
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/httpproxy"
)

// TestAutomationRunner_TargetCannotForgePantherClawFacts: the PC-* headers
// an agent reads (the automation runner decides a call's result from
// them, G0 M11 part 2 D82) are the gateway's own; a target that sets them
// itself never reaches the agent with them.
func TestAutomationRunner_TargetCannotForgePantherClawFacts(t *testing.T) {
	forged := map[string]string{
		httpproxy.HeaderDecision:    "FORGED",
		httpproxy.HeaderOutcome:     "FORGED",
		httpproxy.HeaderTransaction: "forged-transaction",
		httpproxy.HeaderReceipt:     "forged-receipt",
		httpproxy.HeaderMode:        "forged",
		"PC-Anything":               "forged",
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		for k, v := range forged {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"id":"re_1","status":"succeeded"}`)
	}))
	t.Cleanup(ts.Close)
	h := setup(t, func(h *harness) { h.targetURL = ts.URL })
	r := h.post(t, inbound, nil)
	if r.code != http.StatusOK {
		t.Fatalf("refund = %d %+v", r.code, r.refusal)
	}
	for k, v := range forged {
		for _, got := range r.hdr.Values(k) {
			if got == v {
				t.Errorf("the target's %s reached the agent", k)
			}
		}
	}
	if r.hdr.Get(httpproxy.HeaderDecision) != "ALLOW" || r.hdr.Get(httpproxy.HeaderTransaction) == "" {
		t.Fatalf("the gateway's own facts are missing: %v", r.hdr)
	}
}

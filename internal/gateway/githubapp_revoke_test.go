// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"net/http"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/sim/github"
)

// TestHR203_ATokenLeftValidIsReportedWhateverItWasFor (#261 review
// follow-up, ADR-0021 item 6): when GitHub refuses to revoke a token, the
// gateway reports it to the server for a fact read and a verification
// read, as it does for a dispatch with the dispatch's outcome, and only
// once: a dispatch's is not reported a second time here.
func TestHR203_ATokenLeftValidIsReportedWhateverItWasFor(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w), withFactReports)
	w.sim.SetFaults(github.Faults{RevokeStatus: http.StatusServiceUnavailable})
	reported := func() []string {
		h.circuitMu.Lock()
		defer h.circuitMu.Unlock()
		return slices.Clone(h.revocations)
	}

	// A dispatch that names no fact: reported with its outcome only.
	if r := h.do(t, http.MethodGet, "/payments/repos/acme/payments/contents/README.md", "", nil); r.code != http.StatusOK {
		t.Fatalf("read = %d %+v", r.code, r.refusal)
	}
	if got := reported(); len(got) != 0 {
		t.Fatalf("a dispatch's token reported here too: %v", got)
	}
	if a := h.auth.snap().records[0].GetCredentialAccess(); a.GetRevocation() != "revoke_failed" {
		t.Fatalf("the dispatch's outcome says %q", a.GetRevocation())
	}

	// A merge reads its facts first: that token is reported.
	if r := h.do(t, http.MethodPut, "/payments/repos/acme/payments/pulls/1/merge", `{"sha":"`+w.head+`"}`, nil); r.code != http.StatusOK {
		t.Fatalf("merge = %d %+v", r.code, r.refusal)
	}
	if got := reported(); !slices.Equal(got, []string{connID + " facts acme/payments"}) {
		t.Fatalf("after the merge's fact read: %v", got)
	}

	// A verification read: reported too.
	if _, err := h.gw.engine.VerifyEffect(t.Context(), h.conn, dispatch.Lease{
		Operation: "github.pull.read", Purpose: "follow_up",
		Request: []byte(`{"mode":"reference","params":{"method":"get"},"target":{"id":"acme/payments#1","type":"github.pull_request"}}`),
	}); err != nil {
		t.Fatal(err)
	}
	if got := reported(); len(got) != 2 || got[1] != connID+" verification acme/payments" {
		t.Fatalf("after the verification read: %v", got)
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"net/http"
	"testing"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestHR660_TheGatewayReportsTheCredentialItOpened: a dispatch that opened
// the connection's sealed credential reports its id and version with the
// outcome, even when nothing could be sent with it; a dispatch that opened
// none, or could not open it, reports none.
// Covers: F952
func TestHR660_TheGatewayReportsTheCredentialItOpened(t *testing.T) {
	used := func(h *harness) *pb.CredentialUsed {
		t.Helper()
		recs := h.auth.snap().records
		if len(recs) != 1 {
			t.Fatalf("%d records", len(recs))
		}
		return recs[0].GetCredentialUsed()
	}
	h := setup(t, withCredential(t, []string{"127.0.0.1"}))
	if r := h.post(t, inbound, nil); r.code != http.StatusOK {
		t.Fatalf("refund = %d %+v", r.code, r.refusal)
	}
	if u := used(h); u.GetCredentialId() != h.conn.Credential.GetId() || u.GetVersion() != 1 {
		t.Fatalf("a placed credential: reported %v, want %s version 1", u, h.conn.Credential.GetId())
	}
	// Opened, then refused for its hosts before any byte left: it was
	// opened for the dispatch, so the record names it.
	h = setup(t, withCredential(t, []string{"payments.example.test"}))
	if r := h.post(t, inbound, nil); r.code != http.StatusBadGateway || h.target.calls() != 0 {
		t.Fatalf("other hosts = %d %+v, target %d", r.code, r.refusal, h.target.calls())
	}
	if u := used(h); u.GetCredentialId() != h.conn.Credential.GetId() || u.GetVersion() != 1 {
		t.Fatalf("an opened credential that could not be placed: reported %v", u)
	}
	for name, opt := range map[string]func(*harness){
		"no credential": func(*harness) {},
		"none held":     func(h *harness) { h.conn.AccessMode = "pantherclaw_held" },
		"cannot be opened": func(h *harness) {
			withCredential(t, []string{"127.0.0.1"})(h)
			h.conn.Credential.Version = 2 // the seal binds version 1
		},
	} {
		h := setup(t, opt)
		h.post(t, inbound, nil)
		if u := used(h); u != nil {
			t.Errorf("%s: reported %v", name, u)
		}
	}
}

// TestHR660_AMintReportsTheAppKey: a dispatch that minted with the
// connection's GitHub App key reports that key's id and version.
// Covers: F952
func TestHR660_AMintReportsTheAppKey(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w))
	r := h.do(t, http.MethodGet, "/payments/repos/acme/payments/contents/README.md", "", nil)
	if r.code != http.StatusOK {
		t.Fatalf("read = %d %s %+v", r.code, r.body, r.refusal)
	}
	recs := h.auth.snap().records
	if len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	}
	if u := recs[0].GetCredentialUsed(); u.GetCredentialId() != h.conn.Credential.GetId() || u.GetVersion() != 1 {
		t.Fatalf("a minted dispatch: reported %v, want %s version 1", u, h.conn.Credential.GetId())
	}
}

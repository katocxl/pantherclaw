// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"testing"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// withRefundDispatch edits the refund's dispatch block of mock-payments:
// extra lands right under "dispatch:", http under "http:".
func withRefundDispatch(extra, http string) func(*harness) {
	return func(h *harness) {
		h.mutatePkg = func(raw []byte) []byte {
			raw = bytes.Replace(raw, []byte("    dispatch:\n      http:\n        method: POST\n        path: /v1/refunds\n"),
				[]byte("    dispatch:\n"+extra+"      http:\n        method: POST\n        path: /v1/refunds\n"+http), 1)
			return raw
		}
	}
}

// TestHR301_ACredentialOutsideItsPatternSendsNothing: a definition's
// credential pattern is checked on the opened credential before any byte
// is sent; a mismatch records FAILED credential_pattern and the target sees
// zero requests, while a matching credential is sent (G0 M14 D8).
func TestHR301_ACredentialOutsideItsPatternSendsNothing(t *testing.T) {
	h := setup(t, withCredential(t, []string{"127.0.0.1"}),
		withRefundDispatch("      credential_pattern: '^(sk|rk)_test_[A-Za-z0-9]{16,}$'\n", ""))
	r := h.post(t, inbound, nil)
	if r.refusal.Error != "credential_pattern" || h.target.calls() != 0 || h.auth.snap().outcome() != pb.Outcome_OUTCOME_FAILED {
		t.Fatalf("%d %+v, target %d, records %v", r.code, r.refusal, h.target.calls(), h.auth.snap().records)
	}
	h = setup(t, withCredential(t, []string{"127.0.0.1"}),
		withRefundDispatch("      credential_pattern: '^pc-test-credential-[a-z-]+$'\n", ""))
	if r := h.post(t, inbound, nil); r.code != 200 || h.target.calls() != 1 || h.auth.snap().outcome() != pb.Outcome_OUTCOME_ACCEPTED {
		t.Fatalf("a matching credential: %d %+v, target %d", r.code, r.refusal, h.target.calls())
	}
}

// TestM14_StaticHeadersAndSuccess: a template's static headers reach the
// target, and a 2xx answer without the success value the definition names
// is FAILED (G0 M14 D8).
func TestM14_StaticHeadersAndSuccess(t *testing.T) {
	h := setup(t, withRefundDispatch("", "        headers:\n          Stripe-Version: 2026-09-30.endive\n"+
		"        success:\n          field: ok\n          equals: true\n"))
	r := h.post(t, inbound, nil)
	if h.target.calls() != 1 {
		t.Fatalf("target %d: %+v", h.target.calls(), r.refusal)
	}
	if _, hdr := h.target.req(0); hdr.Get("Stripe-Version") != "2026-09-30.endive" {
		t.Fatalf("headers %v", hdr)
	}
	if h.auth.snap().outcome() != pb.Outcome_OUTCOME_FAILED || r.refusal.Error != "target_answer_failed" {
		t.Fatalf("an answer without ok: %d %+v %v", r.code, r.refusal, h.auth.snap().records)
	}
}

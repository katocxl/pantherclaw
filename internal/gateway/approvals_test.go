// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	"github.com/katocxl/pantherclaw/internal/approvals/proof/prooftest"
	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
)

// approved makes the fake Authority's permits carry the approval approve
// builds over the permitted action, and pins file as the gateway's
// approver keys ("" pins none).
func approved(t *testing.T, file []byte, approve func(t *testing.T, act string) *proof.Approval) func(*harness) {
	return func(h *harness) {
		if file != nil {
			h.approverKeys = filepath.Join(t.TempDir(), "approver-keys.json")
			if err := os.WriteFile(h.approverKeys, file, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		h.auth.tamper = func(c *claims) { c.Pap.Approval = approve(t, c.Pap.Act) }
	}
}

// TestHR038_TheGatewayChecksApprovalsBeforeBeginDispatch: an approved
// refund whose approver signed the binding with a pinned key is
// dispatched; with no file, an unknown key, another challenge, no user
// verification, another relying party, a binding for another action, too
// few approvers or a tampered signature, the gateway refuses it as
// enforcement_failed / approval_unverified before BeginDispatch, so
// nothing is committed or sent (founder decision 2026-10-10).
func TestHR038_TheGatewayChecksApprovalsBeforeBeginDispatch(t *testing.T) {
	bob, mallory := prooftest.NewApprover(t, webauthntest.ES256), prooftest.NewApprover(t, webauthntest.ES256)
	file := prooftest.File(t, testOrg, bob)
	one := func(signer *prooftest.Approver, edit func(*prooftest.Approver), mutate func(*proof.Approval)) func(t *testing.T, act string) *proof.Approval {
		return func(t *testing.T, act string) *proof.Approval {
			b := prooftest.Binding(t, act, act)
			if edit != nil {
				edit(signer)
			}
			a := prooftest.Approval(b, signer.Assert(t, b.Hash[:], 0))
			if mutate != nil {
				mutate(a)
			}
			return a
		}
	}
	for _, tc := range []struct {
		name    string
		file    []byte
		approve func(t *testing.T, act string) *proof.Approval
		ok      bool
	}{
		{"pinned key", file, one(bob, nil, nil), true},
		{"no file", nil, one(bob, nil, nil), false},
		{"unknown key", file, one(mallory, nil, nil), false},
		{"wrong challenge", file, func(t *testing.T, act string) *proof.Approval {
			b, other := prooftest.Binding(t, act, act), prooftest.Binding(t, act, act)
			return prooftest.Approval(b, bob.Assert(t, other.Hash[:], 0))
		}, false},
		{"no user verification", file, one(bob.With(func(k *webauthntest.Authenticator) { k.NoUV = true }), nil, nil), false},
		{"wrong relying party", file, one(bob.With(func(k *webauthntest.Authenticator) { k.RPID = "evil.example.test" }), nil, nil), false},
		{"another action", file, func(t *testing.T, _ string) *proof.Approval {
			b := prooftest.Binding(t, strings.Repeat("ef", 32), strings.Repeat("ef", 32))
			return prooftest.Approval(b, bob.Assert(t, b.Hash[:], 0))
		}, false},
		{"too few approvers", file, func(t *testing.T, act string) *proof.Approval {
			b := prooftest.Binding(t, act, act, apdomain.Requirement{Kind: apdomain.KindApproval, Role: "approver", Count: 2})
			return prooftest.Approval(b, bob.Assert(t, b.Hash[:], 0))
		}, false},
		{"tampered signature", file, one(bob, nil, func(a *proof.Approval) {
			sig, _ := base64.RawURLEncoding.DecodeString(a.Assertions[0].Signature)
			sig[len(sig)-1] ^= 1
			a.Assertions[0].Signature = proof.B64(sig)
		}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := setup(t, approved(t, tc.file, tc.approve))
			r := h.post(t, inbound, nil)
			s := h.auth.snap()
			if tc.ok {
				if r.code != http.StatusOK || len(s.begins) != 1 || h.target.calls() != 1 {
					t.Fatalf("= %d %+v, begins %d, target calls %d", r.code, r.refusal, len(s.begins), h.target.calls())
				}
				return
			}
			if r.code != http.StatusBadGateway || r.refusal.ErrorClass != string(dispatch.EnforcementFailed) ||
				r.refusal.Error != dispatch.CodeApprovalUnverified {
				t.Fatalf("= %d %+v, want 502 approval_unverified", r.code, r.refusal)
			}
			if len(s.begins) != 0 || h.target.calls() != 0 {
				t.Fatalf("an unverified approval reached BeginDispatch (%d) or the target (%d)", len(s.begins), h.target.calls())
			}
		})
	}
	// A permit without an approval is not checked, with or without a file.
	if r := setup(t).post(t, inbound, nil); r.code != http.StatusOK {
		t.Fatalf("an action without approval = %d %+v", r.code, r.refusal)
	}
}

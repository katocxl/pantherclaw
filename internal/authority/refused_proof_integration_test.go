// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package authority_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/authority/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
)

// TestHR850_AuthorizeAndVerifyRecordRefusedProofs: a proof replayed at
// Authorize is still CANNOT_AUTHORIZE with its PAP-Error code, and is
// recorded once as an identity event naming the instance, the agent and the
// gateway; replays within the minute are refused and not recorded again;
// VerifyWorkload records its own refusals the same way; no transaction is
// recorded for any of them.
func TestHR850_AuthorizeAndVerifyRecordRefusedProofs(t *testing.T) {
	f := setupIdentity(t)
	agent := f.agent(t)
	wl := f.admitted(t, agent)
	run := f.startRun(t, agent, &wl.inst.Instance)
	ok := f.creds(t, wl, wl.token)
	if res := f.authorizeAs(t, wl, run, ok); res.Decision != domain.Allow {
		t.Fatalf("verified workload: %+v", res)
	}
	for range 3 {
		wantDecision(t, "replayed proof", f.authorizeAs(t, wl, run, ok), domain.CannotAuthorize, domain.ReasonIdentityUnverified,
			string(pap.CodeProofReplay))
	}
	const refused = "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.security.workload_proof_refused'"
	if n := f.count(t, refused); n != 1 {
		t.Fatalf("records after three replays: %d, want 1", n)
	}
	if n := f.count(t, refused+" AND convert_from(body, 'UTF8') LIKE '%\"pap_code\":\"proof_replay\"%'"+
		" AND convert_from(body, 'UTF8') LIKE '%"+wl.inst.Instance.String()+"%'"+
		" AND convert_from(body, 'UTF8') LIKE '%"+agent.String()+"%'"+
		" AND convert_from(body, 'UTF8') LIKE '%"+f.gw.ID+"%'"); n != 1 {
		t.Error("the record lacks the code, instance, agent or gateway")
	}

	// VerifyWorkload: another key with the instance's token.
	stranger := f.admitted(t, agent)
	bad := f.creds(t, stranger, wl.token)
	h := authority.NewHandler(f.svc)
	res, err := h.VerifyWorkload(authority.WithGateway(context.Background(), f.gw), &pantherclawv1.VerifyWorkloadRequest{
		Workload: &pantherclawv1.WorkloadCredentials{WorkloadToken: bad.Token, Proof: bad.Proof, BodySha256: bad.BodySHA256[:], Htm: bad.Method, Htu: bad.URL},
	})
	if err != nil || res.GetVerified() || res.GetErrorCode() != string(pap.CodeKeyMismatch) {
		t.Fatalf("another key: %+v, %v", res, err)
	}
	if n := f.count(t, refused+" AND convert_from(body, 'UTF8') LIKE '%\"pap_code\":\"key_mismatch\"%'"); n != 1 {
		t.Errorf("VerifyWorkload's refusal records %d, want 1", n)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.transactions WHERE org_id = $1"); n != 1 {
		t.Errorf("transactions %d, want only the allowed one", n)
	}
}

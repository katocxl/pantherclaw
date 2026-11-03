// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// bearer turns a request into one an MCP access token proved: no key, level
// 0, proof "bearer" (G0 M26 D402).
func bearer(req pipeline.Request) pipeline.Request {
	req.Identity.AttestationLevel, req.Identity.JKT, req.Identity.Proof = 0, "", "bearer"
	return req
}

// TestHR627_BearerProofIsLevelZeroAndPolicyCanRefuseIt (G0 M26 D402,
// HR-627): a bearer workload is level 0, so any attestation requirement
// refuses it, and policy sees `workload.proof` and can refuse bearer
// clients while the same action proven with PAP/1 passes.
// Covers: F912
func TestHR627_BearerProofIsLevelZeroAndPolicyCanRefuseIt(t *testing.T) {
	f := newFx(t)
	get := func() pipeline.Request { return f.parse(f.run, ids.NewV7(), "get_refund", `{"refund":"re_1"}`) }
	expect(t, f.eval(bearer(get())), adomain.Allow, pipeline.ReasonGrantCovers)

	g := f.grant
	g.Revision, g.MinAttestation = 2, 1
	f.w.Grants.Put(g)
	expect(t, f.eval(bearer(get())), adomain.CannotAuthorize, gdomain.ReasonAttestationTooLow)
	expect(t, f.eval(get()), adomain.Allow, pipeline.ReasonGrantCovers)
	g.Revision, g.MinAttestation = 3, 0
	f.w.Grants.Put(g)

	if err := f.w.SetPolicy([]pdomain.Rule{{
		ID: "no-bearer", Kind: pdomain.Forbid, Summary: "no bearer clients", Operations: []string{"payments.refund.get"},
		When: `workload.proof == "bearer" || workload.attestation < 1`, Reason: "BEARER_REFUSED",
	}}, nil); err != nil {
		t.Fatal(err)
	}
	expect(t, f.eval(bearer(get())), adomain.Deny, "BEARER_REFUSED")
	expect(t, f.eval(get()), adomain.Allow, pipeline.ReasonGrantCovers)
}

// TestHR620_TheRunScopeNarrowsTheGrant (G0 M26 D408): a run narrowed to
// some operations is denied any other, though its grant covers it; a run
// without a scope uses the whole grant.
// Covers: F910
func TestHR620_TheRunScopeNarrowsTheGrant(t *testing.T) {
	f := newFx(t)
	run := ids.NewV7()
	f.w.AddRun(run, pipeline.Run{
		AgentID: f.agent, InstanceID: f.instance, Launcher: f.alice, Principal: f.alice, EnvironmentID: f.env,
		GrantID: f.grant.ID, Active: true, ScopeOperations: []string{"payments.refund.get"},
	})
	expect(t, f.call(run, "get_refund", `{"refund":"re_1"}`), adomain.Allow, pipeline.ReasonGrantCovers)
	expect(t, f.call(run, "create_refund", refund("ch_1", "10.00")), adomain.Deny, pipeline.ReasonOutsideRunScope)
	if ev := f.call(f.run, "create_refund", refund("ch_1", "10.00")); ev.Decision == adomain.Deny {
		t.Fatalf("the unscoped run is denied: %s", ev.Decisive().Code)
	}
}

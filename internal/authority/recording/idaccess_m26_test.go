// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording_test

import (
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TestHR627_WorkloadProofAndRunScopeReplay (G0 M26 D402, D408; HR-627): a
// decision on a bearer workload in a narrowed run is recorded with the
// proof and the run's scope, and replays to the same decision: the policy
// refusal of bearer proof, and the scope's denial.
// Covers: F912
func TestHR627_WorkloadProofAndRunScopeReplay(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	policy(t, s, pdomain.Rule{
		ID: "no-bearer-refunds", Kind: pdomain.Forbid, Summary: "no refunds from bearer clients", Operations: []string{"payments.refund.create"},
		When: `workload.proof == "bearer"`, Reason: "BEARER_REFUSED",
	})
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	narrowed := ids.NewV7()
	s.W.AddRun(narrowed, pipeline.Run{
		AgentID: s.Agent, InstanceID: s.Instance, Launcher: s.Alice, Principal: s.Alice, EnvironmentID: s.Env, GrantID: g.ID,
		Active: true, ScopeOperations: []string{"payments.refund.get"},
	})
	asBearer := func(req pipeline.Request) pipeline.Request {
		req.Identity.AttestationLevel, req.Identity.JKT, req.Identity.Proof = 0, "", "bearer"
		return req
	}
	for name, tc := range map[string]struct {
		req  pipeline.Request
		code string
	}{
		"bearer refused by policy": {asBearer(refund(s, s.Run(g.ID, s.Alice), "ch_1", "30.00")), "BEARER_REFUSED"},
		"outside the run's scope":  {refund(s, narrowed, "ch_1", "30.00"), pipeline.ReasonOutsideRunScope},
	} {
		t.Run(name, func(t *testing.T) {
			orig, replayed, gaps := roundTrip(t, s, tc.req)
			if orig.Decision != adomain.Deny || orig.Decisive().Code != tc.code {
				t.Fatalf("original %s %s, want DENY %s", orig.Decision, orig.Decisive().Code, tc.code)
			}
			if len(gaps) > 0 {
				t.Fatalf("gaps: %v", gaps)
			}
			if a, b := view(orig), view(replayed); a != b {
				t.Fatalf("the replay differs:\noriginal %s\nreplayed %s", a, b)
			}
		})
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package invariants_test

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"testing"
	"time"

	"pgregory.net/rapid"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// apaJKT is the workload key the fixture's requests present.
const apaJKT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

// apaOver50 is the grant requirement that holds refunds over 50 USD for one
// approver.
const apaOver50 = `[{"operations": ["payments.refund.create"], "param": "amount", "unless": {"max": {"USD": "50.00"}},
  "approval": {"role": "approver", "count": 1}, "reason": "REFUND_OVER_50"}]`

// apaRefund is a refund the agent asks for: who presents it, and what.
type apaRefund struct {
	run, instance  ids.UUID
	jkt            string
	charge, amount string
}

// apaRequest is w.request for an action id of the test's choosing, so an
// approval recorded for (run, action) is found again.
func apaRequest(w *world, action ids.UUID, r apaRefund) pipeline.Request {
	w.tb.Helper()
	p, err := w.mapper.MCP(context.Background(), mapping.Context{
		Org: org.String(), Env: w.env.String(), RunID: r.run.String(), ActionID: action.String(), AgentInstance: r.instance.String(),
		Connection: w.conn.String(),
	}, "create_refund", jsontext.Value(refundInput(r.charge, r.amount, "")))
	if err != nil {
		w.tb.Fatal(err)
	}
	return pipeline.Request{
		Org: org, Action: p, Identity: pipeline.Identity{InstanceID: r.instance, AgentID: w.agent, AttestationLevel: 1, JKT: r.jkt},
		Gateway: w.gateway.String(),
	}
}

// apaApproved is the APPROVED request a hold and an approval leave for ev.
func apaApproved(ev *pipeline.Evaluation) *pipeline.HoldRequest {
	by := now.Add(15 * time.Minute)
	return &pipeline.HoldRequest{
		ID: ids.NewV7(), State: apdomain.StateApproved, Binding: ev.Hold.Binding.Hash, Deadline: ev.Hold.Deadline,
		Variants: ev.Hold.Display.Variants, Context: ev.Hold.Display.Context, ConsumeBy: &by,
	}
}

// apaRun starts a run of grant bound to instance, launched by alice.
func apaRun(w *world, grant gdomain.GrantID, instance ids.UUID) ids.UUID {
	id := ids.NewV7()
	w.w.AddRun(id, pipeline.Run{AgentID: w.agent, InstanceID: instance, Launcher: w.alice, Principal: w.alice, EnvironmentID: w.env, GrantID: grant, Active: true})
	return id
}

// apaAmount draws a refund over the 50 USD threshold and within the grant,
// other than except.
func apaAmount(t *rapid.T, label, except string) string {
	return rapid.Custom(func(t *rapid.T) string {
		cents := rapid.IntRange(5001, 10000).Draw(t, "cents")
		return fmt.Sprintf("%d.%02d", cents/100, cents%100)
	}).Filter(func(a string) bool { return a != except }).Draw(t, label)
}

// TestINV05_RandomChangesNeverConsumeAnApproval (M5 part 2): an approval
// binds the exact action and its basis. After a held refund's request is
// approved, the identical resubmission is satisfied by it; after one to
// three random material changes (the amount or charge under the same action
// id, a sibling run or a run on another instance carrying the approval,
// another workload key) or basis changes (a grant revision, a guardrail, a
// fact, a published policy, a stricter requirement), the binding differs:
// the action is held again, never satisfied by the approval or allowed.
func TestINV05_RandomChangesNeverConsumeAnApproval(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		w := newWorld(t)
		g := w.grant(rootBounds, w.alice)
		reqs, err := gdomain.DecodeRequirements([]byte(apaOver50))
		if err != nil {
			t.Fatal(err)
		}
		g.Requirements = reqs
		w.w.Grants.Put(g)
		run, action := w.run(g.ID, w.alice), ids.NewV7()
		orig := apaRefund{
			run: run, instance: w.instance, jkt: apaJKT,
			charge: rapid.SampledFrom([]string{"ch_1", "ch_2", "ch_3"}).Draw(t, "charge"), amount: apaAmount(t, "amount", ""),
		}
		ev := w.eval(apaRequest(w, action, orig))
		if ev.Decision != adomain.RequireApproval || ev.Hold == nil {
			t.Fatalf("the refund was not held: %s %s", ev.Decision, ev.Decisive().Code)
		}
		approval := apaApproved(ev)
		w.w.SetHold(run, action, approval)
		if ok := w.eval(apaRequest(w, action, orig)); ok.Decision != adomain.Allow || ok.Hold == nil || !ok.Hold.Satisfied {
			t.Fatalf("the unchanged refund was not satisfied by its approval: %s %s", ok.Decision, ok.Decisive().Code)
		}

		next := orig
		changes := rapid.SliceOfNDistinct(rapid.IntRange(0, 9), 1, 3, func(i int) int { return i }).Draw(t, "changes")
		for _, c := range changes {
			switch c {
			case 0: // another amount under the approved action id
				next.amount = apaAmount(t, "other amount", orig.amount)
			case 1: // another charge under the approved action id
				next.charge = rapid.SampledFrom([]string{"ch_1", "ch_2", "ch_3"}).Filter(func(s string) bool { return s != orig.charge }).Draw(t, "other charge")
			case 2: // a sibling run of the same grant, on the same instance
				next.run = apaRun(w, g.ID, next.instance)
			case 3: // a run of the same grant on another instance of the agent
				next.instance = ids.NewV7()
				next.run = apaRun(w, g.ID, next.instance)
			case 4: // another workload key
				next.jkt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			case 5: // a grant revision
				revised := g
				revised.Revision = 2
				w.w.Grants.Put(revised)
			case 6: // a guardrail at the agent's team, as wide as the grant
				b, err := gdomain.DecodeBounds([]byte(rootBounds))
				if err != nil {
					t.Fatal(err)
				}
				if err := w.w.Grants.PutEnvelope(context.Background(), org, gdomain.Envelope{
					ID: gdomain.NewEnvelopeID(), Org: org, Revision: 1, Scope: gdomain.Scope{Kind: gdomain.ScopeTeam, ID: w.team}, Name: "team", Bounds: b,
				}, false, auditEvent()); err != nil {
					t.Fatal(err)
				}
			case 7: // a fresh fact about every charge
				for _, ch := range []string{"ch_1", "ch_2", "ch_3"} {
					w.w.PutFact(fdomain.Fact{
						Name: "payments.charge.refundable", SubjectType: "payments.charge", SubjectID: ch,
						Value: fdomain.Value{Type: fdomain.TypeBoolean, Bool: true}, ObservedAt: now.Add(-30 * time.Second), ProviderID: ids.NewV7(),
					})
				}
			case 8: // a published policy
				if err := w.w.SetPolicy([]pdomain.Rule{{
					ID: "note", Kind: pdomain.Annotate, Summary: "x", Operations: []string{"payments.*"},
					When: "true", Reason: "NOTED", Labels: map[string]string{"k": "v"},
				}}, nil); err != nil {
					t.Fatal(err)
				}
			case 9: // a stricter requirement
				if err := w.w.SetPolicy([]pdomain.Rule{{
					ID: "two", Kind: pdomain.RequireApproval, Summary: "x", Operations: []string{"payments.refund.create"},
					When: `action.params.amount > money("50", "USD")`, Reason: "TWO_APPROVERS",
					Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 2},
				}}, nil); err != nil {
					t.Fatal(err)
				}
			}
		}
		if next.run != run {
			w.w.SetHold(next.run, action, approval) // the approval carried to the other run
		}
		got := w.eval(apaRequest(w, action, next))
		if got.Hold != nil && got.Hold.Satisfied {
			t.Fatalf("changes %v: the approval of another binding satisfied the requirement", changes)
		}
		if got.Decision != adomain.RequireApproval {
			t.Fatalf("changes %v: %s %s, want the action held again", changes, got.Decision, got.Decisive().Code)
		}
	})
}

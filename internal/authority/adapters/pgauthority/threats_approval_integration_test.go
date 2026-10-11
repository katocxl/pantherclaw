// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// apaOtherJKT is a workload key other than the one w.request presents.
const apaOtherJKT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// apaInstance admits another instance of the world's agent.
func apaInstance(w *world) ids.UUID {
	w.t.Helper()
	id := ids.NewV7()
	exec(w.t, w.pool, w.org, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, w.org, id, w.agent, id.String()[:36]+"0000000")
	return id
}

// apaRunOn starts a run of grant bound to instance, launched by alice.
func apaRunOn(w *world, grant gdomain.GrantID, instance ids.UUID) ids.UUID {
	w.t.Helper()
	id := ids.NewV7()
	exec(w.t, w.pool, w.org, `INSERT INTO pc.runs (org_id, id, agent_id, instance_id, environment_id, launcher_user_id, principal_user_id,
		principal_source, grant_id, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $6, 'launcher', $7, now() + interval '8 hours')`,
		w.org, id, w.agent, instance, w.env, w.alice, grant.UUID())
	return id
}

// apaRequestFrom is the 85 USD refund of ch_1 as instance presents it, with
// its own key.
func apaRequestFrom(w *world, instance, run, action ids.UUID) pipeline.Request {
	w.t.Helper()
	p, err := w.mapper.MCP(context.Background(), mapping.Context{
		Org: w.org.String(), Env: w.env.String(), RunID: run.String(), ActionID: action.String(), AgentInstance: instance.String(),
		Connection: w.conn.String(),
	}, "create_refund", []byte(`{"charge":"ch_1","amount":"85.00","currency":"USD","reason":"duplicate"}`))
	if err != nil {
		w.t.Fatal(err)
	}
	return pipeline.Request{Org: w.org, Action: p, Identity: pipeline.Identity{InstanceID: instance, AgentID: w.agent, AttestationLevel: 1, JKT: apaOtherJKT}}
}

// apaHold is a world where the 85 USD refund of ch_1 that act asks for on
// run is held on request, and the request is approved.
type apaHold struct {
	w                 *world
	grant             gdomain.Grant
	run, act, request ids.UUID
	req               pipeline.Request
}

func apaApprovedRefund(t *testing.T) apaHold {
	t.Helper()
	w := newWorld(t)
	// Two minutes old, so a later report always changes the facts digest.
	w.refundableAt(time.Now().Add(-2*time.Minute), "ch_1")
	w.refundableAt(time.Now().Add(-2*time.Minute), "ch_2")
	g := w.heldGrant()
	h := apaHold{w: w, grant: g, run: w.run(g.ID, ids.UUID{}), act: ids.NewV7()}
	h.req = w.request(h.run, h.act, "ch_1", "85.00")
	h.request = held(t, w.authorize(h.req))
	w.approve(h.request)
	return h
}

// TestT005_ASiblingRunOrInstanceNeverUsesAnotherRunsApproval: T-005 — run
// A's 85 USD refund is approved. A sibling run of the same agent and grant,
// and a run on another instance of the agent, submit the identical refund
// under the same action id: each is held on a request of its own, and A's
// approval stays unused. A then uses it for exactly one permit, and no
// resubmission, sibling or new action id gets another. The binding's run,
// instance and key are TestHR030_SiblingRunOrOtherInstanceOrKeyNeverMatches;
// one consumption under concurrency is TestRace_ApprovalConsumedOnce.
func TestT005_ASiblingRunOrInstanceNeverUsesAnotherRunsApproval(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	g := w.heldGrant()
	runA, act := w.run(g.ID, ids.UUID{}), ids.NewV7()
	reqA := w.request(runA, act, "ch_1", "85.00")
	approved := held(t, w.authorize(reqA))
	w.approve(approved)
	other := apaInstance(w)
	siblings := []pipeline.Request{
		w.request(w.run(g.ID, ids.UUID{}), act, "ch_1", "85.00"),
		apaRequestFrom(w, other, apaRunOn(w, g.ID, other), act),
	}
	for i, req := range siblings {
		if own := held(t, w.authorize(req)); own == approved {
			t.Fatalf("sibling %d was given run A's request", i)
		}
	}
	if s := w.str("SELECT state FROM pc.approval_requests WHERE id = $1", approved); s != "APPROVED" {
		t.Fatalf("run A's request %s after its siblings, want APPROVED and unused", s)
	}
	ok := w.authorize(reqA)
	if ok.Decision != adomain.Allow || ok.Permit == "" {
		t.Fatalf("run A's approved refund: %s %s", ok.Decision, decisive(ok))
	}
	if s := w.str("SELECT state || '/' || permit_id::text FROM pc.approval_requests WHERE id = $1", approved); s != "CONSUMED/"+ok.PermitID.String() {
		t.Fatalf("run A's request %s", s)
	}
	for i, req := range append(siblings, reqA, w.request(runA, ids.NewV7(), "ch_1", "85.00")) {
		if r := w.authorize(req); r.Permit != "" {
			t.Fatalf("submission %d after the approval was used got a permit: %s %s", i, r.Decision, decisive(r))
		}
	}
	if n := w.count("SELECT count(*) FROM pc.permits"); n != 1 {
		t.Fatalf("%d permits, want only run A's", n)
	}
}

// TestT005_TheApprovedActionReplayedByAnotherKeyOrInstanceGetsNoPermit:
// T-005 — the approved action itself, replayed under another workload key,
// is another binding: it is held again and the approval is superseded,
// never consumed, so even the original key needs a new approval. Replayed
// by another instance of the agent under the same run and action id it is
// another action, denied ACTION_TAMPERED (HR-006), and the original stays
// denied.
func TestT005_TheApprovedActionReplayedByAnotherKeyOrInstanceGetsNoPermit(t *testing.T) {
	t.Run("another workload key", func(t *testing.T) {
		h := apaApprovedRefund(t)
		stolen := h.req
		stolen.Identity.JKT = apaOtherJKT
		if again := held(t, h.w.authorize(stolen)); again == h.request {
			t.Fatal("another key kept the approved request")
		}
		if s := h.w.str("SELECT state || '/' || end_reason FROM pc.approval_requests WHERE id = $1", h.request); s != "SUPERSEDED/BINDING_CHANGED" {
			t.Fatalf("the approved request %s", s)
		}
		if r := h.w.authorize(h.req); r.Decision != adomain.RequireApproval || r.Permit != "" {
			t.Fatalf("the original key after the replay: %s %s", r.Decision, decisive(r))
		}
		if n := h.w.count("SELECT count(*) FROM pc.permits"); n != 0 {
			t.Fatalf("%d permits", n)
		}
	})
	t.Run("another instance", func(t *testing.T) {
		h := apaApprovedRefund(t)
		r := h.w.authorize(apaRequestFrom(h.w, apaInstance(h.w), h.run, h.act))
		if r.Decision != adomain.Deny || decisive(r) != adomain.ReasonActionTampered || r.Permit != "" {
			t.Fatalf("another instance replaying the action: %s %s", r.Decision, decisive(r))
		}
		if r := h.w.authorize(h.req); r.Permit != "" || r.Decision != adomain.Deny {
			t.Fatalf("the original after the replay: %s %s", r.Decision, decisive(r))
		}
		if s := h.w.str("SELECT state || '/' || (permit_id IS NULL) FROM pc.approval_requests WHERE id = $1", h.request); s != "APPROVED/true" {
			t.Fatalf("the approved request %s, want never consumed", s)
		}
		if n := h.w.count("SELECT count(*) FROM pc.permits"); n != 0 {
			t.Fatalf("%d permits", n)
		}
	})
}

// TestT006_AChangeAfterApprovalNeverUsesIt: T-006 — after the 85 USD
// refund is approved, the agent changes the amount under the approved
// action id, sends the money to another charge as a new action, or waits
// for a new fact, a grant revision or a new policy, or for the approval to
// lapse. The changed action never gets the approval: it is denied, or held
// on a request of its own while the approved one is superseded or expires;
// only the unchanged action under its own id may still use it. The details
// are TestHR031_* (pipeline), TestHR171_AHoldIsRecordedOnceAndSupersededWhenItsBindingChanges
// and TestHR039_AnExpiredHoldEndsAsDenyAtUse; delivery failure is
// TestHR039_AFailedDeliveryMarksTheEntryAndDecidesNothing.
func TestT006_AChangeAfterApprovalNeverUsesIt(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(t *testing.T, h apaHold) pipeline.Request
		want   adomain.Decision
		code   string
		state  string
		// original: the unchanged approved action still uses its approval.
		original bool
	}{
		{"a higher amount under the approved action id", func(_ *testing.T, h apaHold) pipeline.Request {
			return h.w.request(h.run, h.act, "ch_1", "95.00")
		}, adomain.Deny, adomain.ReasonActionTampered, "APPROVED", false},
		{"another charge as a new action", func(_ *testing.T, h apaHold) pipeline.Request {
			return h.w.request(h.run, ids.NewV7(), "ch_2", "85.00")
		}, adomain.RequireApproval, "REFUND_OVER_50", "APPROVED", true},
		{"a fresh fact", func(_ *testing.T, h apaHold) pipeline.Request {
			h.w.refundable("ch_1")
			return h.req
		}, adomain.RequireApproval, "REFUND_OVER_50", "SUPERSEDED", false},
		{"a grant revision", func(t *testing.T, h apaHold) pipeline.Request {
			g := h.grant
			if _, _, err := h.w.grants.Revise(h.w.human, gapp.ReviseRequest{
				ID: g.ID, Revision: g.Revision, TaskRef: g.TaskRef, Bounds: g.Bounds, Requirements: g.Requirements, Limits: g.Limits,
				Delegation: g.Delegation,
			}); err != nil {
				t.Fatal(err)
			}
			return h.req
		}, adomain.RequireApproval, "REFUND_OVER_50", "SUPERSEDED", false},
		{"a new policy", func(_ *testing.T, h apaHold) pipeline.Request {
			h.w.publishPolicy(1, false, pgHoldOver50)
			return h.req
		}, adomain.RequireApproval, "REFUND_OVER_50", "SUPERSEDED", false},
		{"use after the consume-by time", func(t *testing.T, h apaHold) pipeline.Request {
			h.w.db.AdminExec(t, `UPDATE pc.approval_requests SET approved_at = now() - interval '20 minutes',
				consume_by = now() - interval '1 second' WHERE id = $1`, h.request)
			return h.req
		}, adomain.Deny, apdomain.ReasonApprovalExpired, "EXPIRED", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := apaApprovedRefund(t)
			r := h.w.authorize(c.change(t, h))
			if r.Decision != c.want || decisive(r) != c.code || r.Permit != "" {
				t.Fatalf("the changed action: %s %s, want %s %s and no permit", r.Decision, decisive(r), c.want, c.code)
			}
			if c.want == adomain.RequireApproval && (r.Wait == nil || r.Wait.RequestID == h.request || r.Wait.State != apdomain.WaitPending) {
				t.Fatalf("the changed action is not held on a request of its own: %+v", r.Wait)
			}
			if s := h.w.str("SELECT state FROM pc.approval_requests WHERE id = $1", h.request); s != c.state {
				t.Fatalf("the approved request %s, want %s", s, c.state)
			}
			if c.original {
				if ok := h.w.authorize(h.req); ok.Permit == "" ||
					h.w.str("SELECT state FROM pc.approval_requests WHERE id = $1", h.request) != "CONSUMED" {
					t.Fatalf("the unchanged approved action: %s %s", ok.Decision, decisive(ok))
				}
				return
			}
			if again := h.w.authorize(h.req); again.Permit != "" {
				t.Fatalf("the approved action after the change: %s %s", again.Decision, decisive(again))
			}
			if n := h.w.count("SELECT count(*) FROM pc.permits"); n != 0 {
				t.Fatalf("%d permits", n)
			}
		})
	}
}

// TestT007_VariantShoppingIsCappedSignalledAndNeverQueued: T-007 — an agent
// asks for refund after refund of one charge, each a little smaller, to
// wear its approvers down. Its run holds at most 5: the third variant on
// raises security.variant_suspected, approvers see the earlier variants on
// the request, and the sixth and seventh are refused HOLD_LIMIT_REACHED
// with no request or Waitlist entry. More runs on the same grant stop at
// the grant's 20. The caps under concurrency are TestRace_HoldCapUnderConcurrency;
// the notice to security admins TestHR037_TheThirdVariantTellsTheSecurityAdmins.
func TestT007_VariantShoppingIsCappedSignalledAndNeverQueued(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	g := w.heldGrant()
	run := w.run(g.ID, ids.UUID{})
	var requests []ids.UUID
	for i := range 7 {
		r := w.authorize(w.request(run, ids.NewV7(), "ch_1", fmt.Sprintf("%d.00", 85-i)))
		if i < 5 {
			requests = append(requests, held(t, r))
			continue
		}
		if r.Decision != adomain.CannotAuthorize || decisive(r) != apdomain.ReasonHoldLimitReached || r.Wait != nil {
			t.Fatalf("variant %d over the run's cap: %s %s %+v", i+1, r.Decision, decisive(r), r.Wait)
		}
	}
	if n := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.security.variant_suspected'"); n != 3 {
		t.Fatalf("%d variant signals, want one for each of the third to fifth", n)
	}
	if n := w.count("SELECT count(*) FROM pc.approval_requests"); n != 5 {
		t.Fatalf("%d requests, want the refused variants never recorded", n)
	}
	if n := w.count("SELECT count(*) FROM pc.waitlist_entries WHERE kind = 'ACTION_HOLD'"); n != 5 {
		t.Fatalf("%d hold entries, want the refused variants never queued", n)
	}
	if n := w.count("SELECT jsonb_array_length(display->'variants') FROM pc.approval_requests WHERE id = $1", requests[4]); n != 4 {
		t.Fatalf("the fifth request shows %d earlier variants, want 4", n)
	}
	for range 3 {
		more := w.run(g.ID, ids.UUID{})
		for i := range 5 {
			held(t, w.authorize(w.request(more, ids.NewV7(), "ch_1", fmt.Sprintf("7%d.00", i))))
		}
	}
	r := w.authorize(w.request(w.run(g.ID, ids.UUID{}), ids.NewV7(), "ch_1", "61.00"))
	if r.Decision != adomain.CannotAuthorize || decisive(r) != apdomain.ReasonHoldLimitReached {
		t.Fatalf("a fresh run past the grant's cap: %s %s", r.Decision, decisive(r))
	}
	if n := w.count("SELECT pending FROM pc.hold_slots WHERE scope_kind = 'grant' AND scope_id = $1", g.ID.UUID()); n != 20 {
		t.Fatalf("grant slots %d, want the cap of 20", n)
	}
}

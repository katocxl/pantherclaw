// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"strings"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TestHR207_AReleaseApprovalCountsOnlyInsideAChangeWindow: a refund that
// starts a payout to the payroll environment needs the payout's approval
// with window: true. Approved, it is consumed only by a finalization
// inside an active change window for payroll, by the database clock:
// without a window, and under a freeze, the answer is CANNOT_AUTHORIZE
// CHANGE_WINDOW_CLOSED and the approval stays unconsumed; inside the
// window the resubmission is allowed and consumes it. A release_approver
// requirement counts only inside a window by its role alone (HR-207), even
// without window: true.
func TestHR207_AReleaseApprovalCountsOnlyInsideAChangeWindow(t *testing.T) {
	for _, req := range []pdomain.ApprovalRequirement{{Role: "approver", Count: 1, Window: true}, {Role: "release_approver", Count: 1}} {
		t.Run(req.Role, func(t *testing.T) { releaseInsideAWindow(t, req) })
	}
}

func releaseInsideAWindow(t *testing.T, approval pdomain.ApprovalRequirement) {
	t.Helper()
	w := newWorldWith(t, pipelinetest.PayoutConsequence)
	w.refundable("ch_1")
	w.payouts("ch_1", `{"state": "scheduled", "environments": ["payroll"]}`)
	b, _ := gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.create", "payments.payout.trigger"],
	  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}}`))
	g, err := w.grants.Issue(w.human, gapp.IssueRequest{
		AgentID: w.agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.alice}, TaskRef: "refunds",
		ExpiresAt: time.Now().Add(48 * time.Hour), Bounds: b, Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 5},
		Requirements: []gdomain.Requirement{{
			Operations: gdomain.Ops{"payments.payout.trigger"}, Reason: "PAYOUTS_NEED_A_RELEASE",
			Approval: &approval,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := w.request(w.run(g.ID, ids.UUID{}), ids.NewV7(), "ch_1", "30.00")
	request := held(t, w.authorize(req))
	w.approveAs(request, approval.Role)
	closed := func(want string) {
		t.Helper()
		r := w.authorize(req)
		if r.Decision != adomain.CannotAuthorize || decisive(r) != finalize.ReasonWindowClosed || !strings.Contains(r.Reasons[0].Detail, want) {
			t.Fatalf("outside a window: %s %s %+v", r.Decision, decisive(r), r.Reasons)
		}
		if s := w.str("SELECT state FROM pc.approval_requests WHERE id = $1", request); s != "APPROVED" {
			t.Fatalf("the approval was used outside a window: %s", s)
		}
	}
	closed("payroll is NO_WINDOW")

	const window = `INSERT INTO pc.change_windows (org_id, id, environment, time_zone, one_off, freezes, revision, created_by)
		VALUES ($1, $2, 'payroll', 'UTC', jsonb_build_array(jsonb_build_object('start', now() - interval '1 hour', 'end', now() + interval '1 hour')),
		$3::jsonb, $4, 'test')`
	frozen := ids.NewV7()
	exec(t, w.pool, w.org, window, w.org, frozen,
		`[{"start": "`+time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)+`", "end": "`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}]`, 1)
	closed("payroll is FROZEN")

	exec(t, w.pool, w.org, `UPDATE pc.change_windows SET state = 'RETIRED', retired_by = 'test', retired_at = now() WHERE id = $1`, frozen)
	exec(t, w.pool, w.org, window, w.org, ids.NewV7(), `[]`, 2)
	r := w.authorize(req)
	if r.Decision != adomain.Allow || r.Permit == "" {
		t.Fatalf("inside the window: %s %s", r.Decision, decisive(r))
	}
	if s := w.str("SELECT state FROM pc.approval_requests WHERE id = $1", request); s != "CONSUMED" {
		t.Fatalf("the approval was not consumed inside the window: %s", s)
	}
}

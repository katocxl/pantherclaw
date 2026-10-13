// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"encoding/json/jsontext"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// heldRefunds issues a refund grant whose refunds need reqs.
func (w *world) heldRefunds(ops []string, reqs ...gdomain.Requirement) gdomain.Grant {
	w.t.Helper()
	b, _ := gdomain.DecodeBounds([]byte(`{"operations": ["` + strings.Join(ops, `", "`) + `"],
	  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}}`))
	g, err := w.grants.Issue(w.human, gapp.IssueRequest{
		AgentID: w.agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.alice}, TaskRef: "refunds",
		ExpiresAt: time.Now().Add(48 * time.Hour), Bounds: b, Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 5},
		Requirements: reqs,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return g
}

// requestState reads an approval request's state and end reason.
func (w *world) requestState(id ids.UUID) (state, end string) {
	w.t.Helper()
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT state, coalesce(end_reason, '') FROM pc.approval_requests WHERE org_id = $1 AND id = $2`,
			w.org, id).Scan(&state, &end)
	}); err != nil {
		w.t.Fatal(err)
	}
	return state, end
}

// hasReason reports whether a decision gives code among its reasons.
func hasReason(r finalize.Result, code string) bool {
	return slices.ContainsFunc(r.Reasons, func(x adomain.Reason) bool { return x.Code == code })
}

// TestT083_MergeAndReleaseApprovalsCannotBeAbused is T-083 (merge and
// release approval abuse) through the Authority and PostgreSQL, on the
// mock payments package shaped as pc.github's merge (the charge's state
// object as the pull request's head, its people fact as the pull request's
// people, its payouts as the deployments a merge starts):
//   - an approval given for one head is not reused after a new commit: the
//     approved request is superseded, the old head is refused, and a head
//     that matches the approved value again is held anew;
//   - the author and a pusher, colluding as reviewers, are refused;
//   - a consequence whose fact cannot be read is held for the union of the
//     requirements, never allowed on the review alone.
func TestT083_MergeAndReleaseApprovalsCannotBeAbused(t *testing.T) {
	t.Run("an approval is not reused after a new commit", func(t *testing.T) {
		w := newWorldWith(t, boundRefunds)
		w.refundable("ch_1")
		g := w.heldRefunds([]string{"payments.refund.create"}, gdomain.Requirement{
			Operations: gdomain.Ops{"payments.refund.create"}, Reason: "REFUNDS_NEED_APPROVAL",
			Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
		})
		run := w.run(g.ID, ids.UUID{})
		w.state("ch_1", "duplicate") // the head the approval is for
		action := ids.NewV7()
		r := w.authorize(w.request(run, action, "ch_1", "30.00"))
		if r.Decision != adomain.RequireApproval || r.Wait == nil {
			t.Fatalf("held: %s %+v", r.Decision, r.Wait)
		}
		approved := r.Wait.RequestID
		w.approve(approved)
		if state, _ := w.requestState(approved); state != "APPROVED" {
			t.Fatalf("approved: %s", state)
		}

		w.state("ch_1", "fraudulent") // a new commit moves the head
		if state, end := w.requestState(approved); state != "SUPERSEDED" || end != "BINDING_CHANGED" {
			t.Fatalf("the approval after the head moved: %s %s", state, end)
		}
		if r := w.authorize(w.request(run, action, "ch_1", "30.00")); r.Decision == adomain.Allow || decisive(r) != "STATE_MOVED" {
			t.Fatalf("the approved action at the old head: %s %s", r.Decision, decisive(r))
		}
		// Even when a later commit brings back the approved value, the
		// superseded approval is not used: the same action is held again.
		w.state("ch_1", "duplicate")
		r = w.authorize(w.request(run, action, "ch_1", "30.00"))
		if r.Decision != adomain.RequireApproval || r.Wait == nil || r.Wait.RequestID == approved {
			t.Fatalf("the approved action at a head that matches again: %s %+v", r.Decision, r.Wait)
		}
		if state, _ := w.requestState(approved); state != "SUPERSEDED" {
			t.Fatalf("the superseded approval came back: %s", state)
		}
	})

	t.Run("the author and a pusher cannot review", func(t *testing.T) {
		w := newWorldWith(t, peopleRefunds)
		w.refundable("ch_1")
		author, pusher := ids.NewV7(), ids.NewV7()
		for gh, u := range map[int64]ids.UUID{42: author, 43: pusher} {
			exec(t, w.pool, w.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", w.org, u, u.String())
			exec(t, w.pool, w.org, `INSERT INTO pc.github_identities (org_id, id, user_id, github_login, github_user_id, linked_by, verified_at)
				VALUES ($1, $2, $3, $4, $5, 'test', now())`, w.org, ids.NewV7(), u, u.String()[:8], gh)
		}
		ctx := tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindServiceAccount, ID: w.billing}}})
		if res, err := w.facts.PutFacts(ctx, []fdomain.Observation{{
			Name: "payments.charge.people", SubjectType: "payments.charge", SubjectID: "ch_1",
			Value: jsontext.Value(`{"object": {"complete": true, "author": 42, "pushers": [42, 43]}}`), ObservedAt: time.Now().Add(-time.Second),
		}}); err != nil || res[0].Err != nil {
			t.Fatalf("people: %v %+v", err, res)
		}
		g := w.heldRefunds([]string{"payments.refund.create"}, gdomain.Requirement{
			Operations: gdomain.Ops{"payments.refund.create"}, Reason: "MERGES_NEED_AN_INDEPENDENT_REVIEW",
			Approval: &pdomain.ApprovalRequirement{Role: "code_reviewer", Count: 1},
		})
		r := w.authorize(w.request(w.run(g.ID, ids.UUID{}), ids.NewV7(), "ch_1", "30.00"))
		if r.Decision != adomain.RequireApproval || r.Wait == nil {
			t.Fatalf("held: %s %+v", r.Decision, r.Wait)
		}
		var e pgapprovals.Eligibility
		if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			e, err = pgapprovals.LoadEligibility(ctx, dbq.New(tx), w.org, r.Wait.RequestID, []ids.UUID{author, pusher})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		for name, u := range map[string]ids.UUID{"the author": author, "a pusher": pusher} {
			reviewer := apdomain.Person{
				UserID: u, Enabled: true, JoinedAt: time.Now().Add(-90 * 24 * time.Hour), GitHubVerified: e.People[u].GitHubVerified,
				Bindings:    []apdomain.RoleBinding{{Role: "code_reviewer", CreatedAt: time.Now().Add(-90 * 24 * time.Hour)}},
				Credentials: []apdomain.Credential{{ID: ids.NewV7(), CreatedAt: time.Now().Add(-90 * 24 * time.Hour)}},
			}
			if ok, code := apdomain.Check(e.Requirements[0], reviewer, e.Context, ids.UUID{}); ok || code != apdomain.IneligibleAuthor {
				t.Fatalf("%s as reviewer: %v %s", name, ok, code)
			}
		}
	})

	t.Run("a consequence whose fact cannot be read holds for every requirement", func(t *testing.T) {
		w := newWorldWith(t, pipelinetest.PayoutConsequence)
		w.refundable("ch_1", "ch_2")
		g := w.heldRefunds([]string{"payments.refund.create", "payments.payout.trigger"},
			gdomain.Requirement{
				Operations: gdomain.Ops{"payments.refund.create"}, Reason: "MERGES_NEED_AN_INDEPENDENT_REVIEW",
				Approval: &pdomain.ApprovalRequirement{Role: "code_reviewer", Count: 1},
			},
			gdomain.Requirement{
				Operations: gdomain.Ops{"payments.payout.trigger"}, Reason: "DEPLOYMENTS_NEED_A_RELEASE",
				Approval: &pdomain.ApprovalRequirement{Role: "release_approver", Count: 1},
			})
		run := w.run(g.ID, ids.UUID{})
		// No payouts fact for ch_1: what the refund starts cannot be read.
		r := w.authorize(w.request(run, ids.NewV7(), "ch_1", "30.00"))
		if r.Decision != adomain.RequireApproval || r.Wait == nil || !hasReason(r, "CONSEQUENCE_UNKNOWN") ||
			!hasReason(r, "MERGES_NEED_AN_INDEPENDENT_REVIEW") || !hasReason(r, "DEPLOYMENTS_NEED_A_RELEASE") {
			t.Fatalf("a missing consequence fact: %s %+v", r.Decision, r.Reasons)
		}
		var e pgapprovals.Eligibility
		if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			e, err = pgapprovals.LoadEligibility(ctx, dbq.New(tx), w.org, r.Wait.RequestID, nil)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		var roles []string
		for _, req := range e.Requirements {
			roles = append(roles, req.Role)
		}
		if !slices.Contains(roles, "code_reviewer") || !slices.Contains(roles, "release_approver") {
			t.Fatalf("the held request asks for %v: a review alone would release it", roles)
		}
		// The same refund whose payouts are read as none needs the review only.
		w.payouts("ch_2", `{"state": "none", "environments": []}`)
		r = w.authorize(w.request(run, ids.NewV7(), "ch_2", "30.00"))
		if r.Decision != adomain.RequireApproval || hasReason(r, "CONSEQUENCE_UNKNOWN") || hasReason(r, "DEPLOYMENTS_NEED_A_RELEASE") {
			t.Fatalf("no consequence: %s %+v", r.Decision, r.Reasons)
		}
	})
}

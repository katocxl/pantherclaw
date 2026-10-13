// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"encoding/json/jsontext"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
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

// TestHR207_AGitHubReviewerNeedsAProvenLinkAndStaysExcluded (founder
// decision 2026-10-13, P2f): a code reviewer counts only with a GitHub link
// they proved by signing in to GitHub; the pull request's author, a commit
// author and a pusher are refused; and the people linked when the request
// was created stay excluded, so a reviewer who unlinks, approves and links
// another account is refused at every step. Whoever ever proved a link to
// a listed account stays excluded from later requests too, after moving
// the account to someone else, who is excluded as well (review 2026-10-13).
func TestHR207_AGitHubReviewerNeedsAProvenLinkAndStaysExcluded(t *testing.T) {
	w := newWorldWith(t, peopleRefunds)
	w.refundable("ch_1")
	ctx := tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{
		Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindServiceAccount, ID: w.billing},
	}})
	res, err := w.facts.PutFacts(ctx, []fdomain.Observation{{
		Name: "payments.charge.people", SubjectType: "payments.charge", SubjectID: "ch_1",
		Value:      jsontext.Value(`{"object": {"complete": true, "author": 42, "authors": [42, 44], "pushers": [43]}}`),
		ObservedAt: time.Now().Add(-time.Second),
	}})
	if err != nil || res[0].Err != nil {
		t.Fatalf("people: %v %+v", err, res)
	}
	// bob wrote the pull request, carol pushed to it and erin authored one
	// of its commits; dave is linked to an account it does not list, and
	// frank and grace linked none.
	bob, carol, erin, dave, frank, grace := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	everyone := []ids.UUID{bob, carol, erin, dave, frank, grace}
	for i, u := range everyone {
		exec(t, w.pool, w.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", w.org, u, "p"+string(rune('a'+i)))
	}
	link := func(u ids.UUID, gh int64) {
		t.Helper()
		exec(t, w.pool, w.org, `INSERT INTO pc.github_identities (org_id, id, user_id, github_login, github_user_id, linked_by, verified_at)
			VALUES ($1, $2, $3, $4, $5, 'test', now())`, w.org, ids.NewV7(), u, "gh"+ids.NewV7().String()[30:], gh)
		exec(t, w.pool, w.org, "INSERT INTO pc.github_identity_history (org_id, github_user_id, user_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", w.org, gh, u)
	}
	for u, gh := range map[ids.UUID]int64{bob: 42, carol: 43, erin: 44, dave: 45} {
		link(u, gh)
	}
	b, _ := gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.create"],
	  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}}`))
	g, err := w.grants.Issue(w.human, gapp.IssueRequest{
		AgentID: w.agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.alice}, TaskRef: "refunds",
		ExpiresAt: time.Now().Add(48 * time.Hour), Bounds: b, Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 5},
		Requirements: []gdomain.Requirement{{
			Operations: gdomain.Ops{"payments.refund.create"}, Reason: "REFUNDS_NEED_REVIEW",
			Approval: &pdomain.ApprovalRequirement{Role: "code_reviewer", Count: 1},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hold := func(amount string) ids.UUID {
		t.Helper()
		r := w.authorize(w.request(w.run(g.ID, ids.UUID{}), ids.NewV7(), "ch_1", amount))
		if r.Decision != adomain.RequireApproval || r.Wait == nil {
			t.Fatalf("held: %s %+v", r.Decision, r.Wait)
		}
		return r.Wait.RequestID
	}
	request := hold("30.00")
	check := func(u ids.UUID) string {
		t.Helper()
		var e pgapprovals.Eligibility
		if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			e, err = pgapprovals.LoadEligibility(ctx, dbq.New(tx), w.org, request, everyone)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		p := e.People[u]
		p.Bindings = []apdomain.RoleBinding{{Role: "code_reviewer", CreatedAt: time.Now().Add(-90 * 24 * time.Hour)}}
		p.Credentials = []apdomain.Credential{{ID: ids.NewV7(), CreatedAt: time.Now().Add(-90 * 24 * time.Hour)}}
		p.JoinedAt = time.Now().Add(-90 * 24 * time.Hour)
		_, code := apdomain.Check(e.Requirements[0], p, e.Context, ids.UUID{})
		return code
	}
	for name, c := range map[string]struct {
		user ids.UUID
		want string
	}{
		"the author":                    {bob, apdomain.IneligibleAuthor},
		"a pusher":                      {carol, apdomain.IneligibleAuthor},
		"a commit's author":             {erin, apdomain.IneligibleAuthor},
		"someone without a GitHub link": {frank, apdomain.IneligibleNotLinked},
		"a linked reviewer":             {dave, ""},
	} {
		if got := check(c.user); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	if n := w.str("SELECT count(*)::text FROM pc.approval_request_linked_people WHERE request_id = $1", request); n != "3" {
		t.Fatalf("%s people kept as linked at the request's creation, want 3", n)
	}

	// The author unlinks, so the fact no longer names a user of theirs: they
	// stay excluded from this request, and once they link another account too.
	exec(t, w.pool, w.org, "DELETE FROM pc.github_identities WHERE user_id = $1", bob)
	if got := check(bob); got != apdomain.IneligibleAuthor {
		t.Fatalf("the author, unlinked: %q", got)
	}
	link(bob, 47)
	if got := check(bob); got != apdomain.IneligibleAuthor {
		t.Fatalf("the author, linked to another account: %q", got)
	}
	// frank links an account the fact does not list: now he may review.
	link(frank, 46)
	if got := check(frank); got != "" {
		t.Fatalf("frank, linked: %q", got)
	}

	// grace now holds the author's account. On a request held after that, the
	// author is still excluded, having proved a link to it once, and so is
	// grace; a manager unlinking grace changes nothing.
	link(grace, 42)
	request = hold("40.00")
	for name, u := range map[string]ids.UUID{"the author, who moved the account": bob, "who holds it now": grace} {
		if got := check(u); got != apdomain.IneligibleAuthor {
			t.Errorf("%s: %q", name, got)
		}
	}
	exec(t, w.pool, w.org, "DELETE FROM pc.github_identities WHERE user_id = $1", grace)
	if got := check(grace); got != apdomain.IneligibleAuthor {
		t.Fatalf("grace, unlinked by a manager: %q", got)
	}

	// Through the Authority (review 2026-10-13): an approval by a code reviewer
	// without a GitHub link is voided when it is used (NOT_ELIGIBLE), the
	// request is pending again and no permit is issued; a reviewer with a
	// proved link to an account the fact does not list approves it.
	req := w.request(w.run(g.ID, ids.UUID{}), ids.NewV7(), "ch_1", "50.00")
	pending := held(t, w.authorize(req))
	w.approveAs(pending, "code_reviewer")
	if r := w.authorize(req); r.Permit != "" {
		t.Fatalf("an unlinked reviewer's approval was used: %s %s", r.Decision, decisive(r))
	}
	if s := w.str(`SELECT r.state || '/' || string_agg(coalesce(p.void_reason, ''), ',') FROM pc.approval_requests r
		JOIN pc.approval_responses p ON p.org_id = r.org_id AND p.request_id = r.id WHERE r.id = $1 GROUP BY r.state`, pending); s != "PENDING/NOT_ELIGIBLE" {
		t.Fatalf("after the unlinked approval: %s", s)
	}
	reviewer := w.approveAs(pending, "code_reviewer")
	var reviewerUser ids.UUID
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT user_id FROM pc.role_bindings WHERE id = $1", reviewer).Scan(&reviewerUser)
	}); err != nil {
		t.Fatal(err)
	}
	link(reviewerUser, 48)
	if r := w.authorize(req); r.Permit == "" {
		t.Fatalf("a linked reviewer's approval: %s %s", r.Decision, decisive(r))
	}
}

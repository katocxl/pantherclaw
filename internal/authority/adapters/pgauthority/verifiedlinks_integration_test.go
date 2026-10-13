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
// again is refused at every step.
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
	// frank linked none.
	bob, carol, erin, dave, frank := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	everyone := []ids.UUID{bob, carol, erin, dave, frank}
	for i, u := range everyone {
		exec(t, w.pool, w.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", w.org, u, "p"+string(rune('a'+i)))
	}
	link := func(u ids.UUID, gh int64) {
		t.Helper()
		exec(t, w.pool, w.org, `INSERT INTO pc.github_identities (org_id, id, user_id, github_login, github_user_id, linked_by, verified_at)
			VALUES ($1, $2, $3, $4, $5, 'test', now())`, w.org, ids.NewV7(), u, "gh"+ids.NewV7().String()[30:], gh)
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
	r := w.authorize(w.request(w.run(g.ID, ids.UUID{}), ids.NewV7(), "ch_1", "30.00"))
	if r.Decision != adomain.RequireApproval || r.Wait == nil {
		t.Fatalf("held: %s %+v", r.Decision, r.Wait)
	}
	check := func(u ids.UUID) string {
		t.Helper()
		var e pgapprovals.Eligibility
		if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			e, err = pgapprovals.LoadEligibility(ctx, dbq.New(tx), w.org, r.Wait.RequestID, everyone)
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
	if n := w.str("SELECT count(*)::text FROM pc.approval_request_linked_people WHERE request_id = $1", r.Wait.RequestID); n != "3" {
		t.Fatalf("%s people kept as linked at the request's creation, want 3", n)
	}

	// The author unlinks, so the fact no longer names a user of theirs: they
	// stay excluded from this request, and once they link again too.
	exec(t, w.pool, w.org, "DELETE FROM pc.github_identities WHERE user_id = $1", bob)
	if got := check(bob); got != apdomain.IneligibleAuthor {
		t.Fatalf("the author, unlinked: %q", got)
	}
	link(bob, 42)
	if got := check(bob); got != apdomain.IneligibleAuthor {
		t.Fatalf("the author, linked again: %q", got)
	}
	// frank links an account the fact does not list: now he may review.
	link(frank, 46)
	if got := check(frank); got != "" {
		t.Fatalf("frank, linked: %q", got)
	}
}

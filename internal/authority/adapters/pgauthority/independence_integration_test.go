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
	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
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

// peopleRefunds names the charge's people fact as the one an independent
// refund approver must not be in, as pc.github's merge names
// github.pull.people.
func peopleRefunds(pkg string) string {
	pkg = strings.Replace(pkg, "      - fact: payments.charge.refundable\n        max_age_seconds: 300\n",
		"      - fact: payments.charge.refundable\n        max_age_seconds: 300\n      - fact: payments.charge.people\n        max_age_seconds: 300\n", 1)
	return strings.Replace(pkg, "      fields: [params.amount, params.reason, target.id]\n",
		"      fields: [params.amount, params.reason, target.id]\n      independent_of: payments.charge.people\n", 1)
}

// TestHR207_TheLinkedPeopleOfTheHeldActionAreNotIndependent: when a person
// responds, the approvals side reads the held action's people fact as it
// is now and excludes the users linked to the GitHub users it lists (an
// author, a pusher), never an unlinked person; a fact that says it is
// incomplete leaves nobody independent.
func TestHR207_TheLinkedPeopleOfTheHeldActionAreNotIndependent(t *testing.T) {
	w := newWorldWith(t, peopleRefunds)
	w.refundable("ch_1")
	people := func(object string) {
		t.Helper()
		ctx := tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindServiceAccount, ID: w.billing}}})
		res, err := w.facts.PutFacts(ctx, []fdomain.Observation{{
			Name: "payments.charge.people", SubjectType: "payments.charge", SubjectID: "ch_1",
			Value: jsontext.Value(`{"object": ` + object + `}`), ObservedAt: time.Now().Add(-time.Second),
		}})
		if err != nil || res[0].Err != nil {
			t.Fatalf("people: %v %+v", err, res)
		}
	}
	bob, carol, dave := ids.NewV7(), ids.NewV7(), ids.NewV7()
	for i, u := range []ids.UUID{bob, carol, dave} {
		exec(t, w.pool, w.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", w.org, u, "u"+string(rune('a'+i)))
	}
	for gh, u := range map[int64]ids.UUID{42: bob, 43: carol} {
		exec(t, w.pool, w.org, `INSERT INTO pc.github_identities (org_id, id, user_id, github_login, github_user_id, linked_by)
			VALUES ($1, $2, $3, $4, $5, 'test')`, w.org, ids.NewV7(), u, "gh"+strings.Repeat("x", int(gh-41)), gh)
	}
	b, _ := gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.create"],
	  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}}`))
	g, err := w.grants.Issue(w.human, gapp.IssueRequest{
		AgentID: w.agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.alice}, TaskRef: "refunds",
		ExpiresAt: time.Now().Add(48 * time.Hour), Bounds: b, Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 5},
		Requirements: []gdomain.Requirement{{
			Operations: gdomain.Ops{"payments.refund.create"}, Reason: "REFUNDS_NEED_APPROVAL",
			Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1, Independent: true},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	people(`{"complete": true, "author": 42, "pushers": [43, 44]}`)
	r := w.authorize(w.request(w.run(g.ID, ids.UUID{}), ids.NewV7(), "ch_1", "30.00"))
	if r.Decision != adomain.RequireApproval || r.Wait == nil {
		t.Fatalf("held: %s %+v", r.Decision, r.Wait)
	}
	load := func() pgapprovals.Eligibility {
		t.Helper()
		var e pgapprovals.Eligibility
		if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			e, err = pgapprovals.LoadEligibility(ctx, dbq.New(tx), w.org, r.Wait.RequestID, []ids.UUID{bob, carol, dave})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := load()
	a := e.Context.Authorship["payments.charge.people"]
	if !a.Complete || len(a.Users) != 2 || !slices.Contains(a.Users, bob) || !slices.Contains(a.Users, carol) || slices.Contains(a.Users, dave) {
		t.Fatalf("authorship %+v", a)
	}
	if len(e.Requirements) != 1 || e.Requirements[0].IndependentOf != "payments.charge.people" {
		t.Fatalf("requirements %+v", e.Requirements)
	}
	someone := func(u ids.UUID) apdomain.Person {
		return apdomain.Person{
			UserID: u, Enabled: true, JoinedAt: time.Now().Add(-90 * 24 * time.Hour),
			Bindings:    []apdomain.RoleBinding{{Role: "approver", CreatedAt: time.Now().Add(-90 * 24 * time.Hour)}},
			Credentials: []apdomain.Credential{{ID: ids.NewV7(), CreatedAt: time.Now().Add(-90 * 24 * time.Hour)}},
		}
	}
	if ok, code := apdomain.Check(e.Requirements[0], someone(carol), e.Context, ids.UUID{}); ok || code != apdomain.IneligibleAuthor {
		t.Fatalf("a linked pusher: %v %s", ok, code)
	}
	if ok, code := apdomain.Check(e.Requirements[0], someone(dave), e.Context, ids.UUID{}); !ok {
		t.Fatalf("an unrelated person: %s", code)
	}

	people(`{"complete": false, "author": 42}`)
	if a := load().Context.Authorship["payments.charge.people"]; a.Complete {
		t.Fatalf("incomplete authorship read as complete: %+v", a)
	}
}

// TestF158_TheApprovalPageListsThePeopleTheIndependenceCheckReads (HR-207):
// the approval page lists, from the read the independence check makes,
// every GitHub user the held action's people fact names now, with how it
// names them and the user linked to them or none, and says so when the
// fact does not list everyone or does not name its pushers.
func TestF158_TheApprovalPageListsThePeopleTheIndependenceCheckReads(t *testing.T) {
	w := newWorldWith(t, peopleRefunds)
	w.refundable("ch_1")
	people := func(object string) {
		t.Helper()
		ctx := tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindServiceAccount, ID: w.billing}}})
		res, err := w.facts.PutFacts(ctx, []fdomain.Observation{{
			Name: "payments.charge.people", SubjectType: "payments.charge", SubjectID: "ch_1",
			Value: jsontext.Value(`{"object": ` + object + `}`), ObservedAt: time.Now().Add(-time.Second),
		}})
		if err != nil || res[0].Err != nil {
			t.Fatalf("people: %v %+v", err, res)
		}
	}
	bob := ids.NewV7()
	exec(t, w.pool, w.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'bob')", w.org, bob)
	exec(t, w.pool, w.org, `INSERT INTO pc.github_identities (org_id, id, user_id, github_login, github_user_id, linked_by)
		VALUES ($1, $2, $3, 'bob', 42, 'test')`, w.org, ids.NewV7(), bob)
	b, _ := gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.create"],
	  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}}`))
	g, err := w.grants.Issue(w.human, gapp.IssueRequest{
		AgentID: w.agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.alice}, TaskRef: "refunds",
		ExpiresAt: time.Now().Add(48 * time.Hour), Bounds: b, Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 5},
		Requirements: []gdomain.Requirement{{
			Operations: gdomain.Ops{"payments.refund.create"}, Reason: "REFUNDS_NEED_APPROVAL",
			Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1, Independent: true},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	people(`{"complete": true, "author": 42, "authors": [42, 43], "pushers": [44]}`)
	r := w.authorize(w.request(w.run(g.ID, ids.UUID{}), ids.NewV7(), "ch_1", "30.00"))
	if r.Decision != adomain.RequireApproval || r.Wait == nil {
		t.Fatalf("held: %s %+v", r.Decision, r.Wait)
	}
	svc := &approvals.Service{Pool: w.pool}
	page := func() apdomain.PeopleList {
		t.Helper()
		v, err := svc.View(w.human, r.Wait.RequestID)
		if err != nil || len(v.People) != 1 {
			t.Fatalf("view: %+v, %v", v.People, err)
		}
		return v.People[0]
	}
	type row struct {
		id     int64
		as     string
		linked bool
	}
	rows := func(l apdomain.PeopleList) []row {
		var out []row
		for _, p := range l.People {
			if p.User != nil && *p.User != bob {
				t.Fatalf("GitHub user %d linked to %s, want bob", p.GitHubID, *p.User)
			}
			out = append(out, row{p.GitHubID, strings.Join(p.As, ", "), p.User != nil})
		}
		return out
	}
	l := page()
	if l.Fact != "payments.charge.people" || !l.Complete || len(l.Gaps) != 0 ||
		!slices.Equal(rows(l), []row{{42, "author, commit author", true}, {43, "commit author", false}, {44, "pusher", false}}) {
		t.Fatalf("complete list: %+v", l)
	}

	people(`{"complete": false, "author": 42, "pushers": [44]}`)
	if l := page(); l.Complete || !slices.Equal(l.Gaps, []string{apdomain.PeopleNotAll}) ||
		!slices.Equal(rows(l), []row{{42, "author", true}, {44, "pusher", false}}) {
		t.Fatalf("incomplete list: %+v", l)
	}
	people(`{"complete": true, "author": 42}`)
	if l := page(); l.Complete || !slices.Equal(l.Gaps, []string{apdomain.PeopleUnnamed}) || !slices.Equal(rows(l), []row{{42, "author", true}}) {
		t.Fatalf("a list without its pushers: %+v", l)
	}
}

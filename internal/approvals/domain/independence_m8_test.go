// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR207_IndependenceExcludesThePullRequestsPeople: an independent
// requirement that names a people fact also excludes the users linked to
// the GitHub users it lists (the pull request's author, committers and
// pushers); a person who is not linked is not excluded, and when the fact
// could not list everyone, nobody counts. A requirement that is not
// independent is unaffected.
func TestHR207_IndependenceExcludesThePullRequestsPeople(t *testing.T) {
	r := approver(1, true)
	r.IndependentOf = "github.pull.people"
	author, other := veteran(), veteran()
	c := ctx()
	c.Authorship = map[string]domain.Authorship{"github.pull.people": {Users: []ids.UUID{author.UserID}, Complete: true}}
	ok, code := domain.Check(r, author, c, ids.UUID{})
	wantCode(t, "a linked author", ok, code, domain.IneligibleAuthor)
	ok, code = domain.Check(r, other, c, ids.UUID{})
	wantCode(t, "someone else", ok, code, "")

	c.Authorship = map[string]domain.Authorship{"github.pull.people": {Users: []ids.UUID{author.UserID}}}
	ok, code = domain.Check(r, other, c, ids.UUID{})
	wantCode(t, "incomplete authorship", ok, code, domain.IneligibleAuthorshipUnknown)
	c.Authorship = nil
	ok, code = domain.Check(r, other, c, ids.UUID{})
	wantCode(t, "authorship not read", ok, code, domain.IneligibleAuthorshipUnknown)

	plain := approver(1, false)
	plain.IndependentOf = "github.pull.people"
	ok, code = domain.Check(plain, author, c, ids.UUID{})
	wantCode(t, "a requirement that is not independent", ok, code, "")
}

// TestHR207_TheReviewerAndTheReleaseApproverAreTwoPeople (design decision
// 7): a merge that also releases a deployment needs a code reviewer and a
// release approver, and one person's response counts toward only one of
// them, so the two are always different people.
func TestHR207_TheReviewerAndTheReleaseApproverAreTwoPeople(t *testing.T) {
	reqs := []domain.Requirement{
		{Kind: domain.KindApproval, Role: "code_reviewer", Count: 1, Independent: true},
		{Kind: domain.KindApproval, Role: "release_approver", Count: 1, Independent: true},
	}
	alice, bob := ids.NewV7(), ids.NewV7()
	both := []domain.Response{
		{UserID: alice, CredentialID: ids.NewV7(), Requirement: 0},
		{UserID: alice, CredentialID: ids.NewV7(), Requirement: 1},
	}
	if domain.Met(reqs, both) {
		t.Fatal("one person reviewed and released")
	}
	if !domain.Met(reqs, []domain.Response{both[0], {UserID: bob, CredentialID: ids.NewV7(), Requirement: 1}}) {
		t.Fatal("two people did not meet both")
	}
}

// TestHR207_OnlyAWellFormedPeopleFactIsComplete: a people fact counts as
// complete only when it says so and names its author and its pushers,
// every id a positive integer; an id given as text, a zero or negative id,
// a missing author or pushers list, or a member that is not a list leaves
// the authorship unknown, never someone dropped from the exclusion.
func TestHR207_OnlyAWellFormedPeopleFactIsComplete(t *testing.T) {
	all, ok := domain.GitHubPeople(map[string]any{
		"complete": true, "author": int64(42), "authors": []any{int64(42), int64(7)}, "committers": []any{int64(8)},
		"pushers": []any{int64(43), int64(7)},
	})
	if !ok || len(all) != 4 {
		t.Fatalf("a full fact, each id once: %v %v", all, ok)
	}
	for name, people := range map[string]map[string]any{
		"not complete":       {"complete": false, "author": int64(42), "pushers": []any{}},
		"no author":          {"complete": true, "pushers": []any{int64(43)}},
		"the author as text": {"complete": true, "author": "42", "pushers": []any{int64(43)}},
		"no pushers":         {"complete": true, "author": int64(42)},
		"a pusher as text":   {"complete": true, "author": int64(42), "pushers": []any{map[string]any{"id": int64(43)}}},
		"a zero id":          {"complete": true, "author": int64(0), "pushers": []any{}},
		"a negative id":      {"complete": true, "author": int64(42), "pushers": []any{int64(-1)}},
		"authors not a list": {"complete": true, "author": int64(42), "authors": int64(7), "pushers": []any{}},
	} {
		if got, ok := domain.GitHubPeople(people); ok || got != nil {
			t.Errorf("%s: %v %v", name, got, ok)
		}
	}
}

// TestHR207_ThePageAndTheCheckAgreeOnACompletePeopleFact: the approval
// page's people list (F158) and the pipeline's AUTHORSHIP_UNKNOWN check
// read a people fact by one rule: a list counts towards independence
// exactly when GitHubPeople finds the fact complete, with the same ids.
func TestHR207_ThePageAndTheCheckAgreeOnACompletePeopleFact(t *testing.T) {
	for name, people := range map[string]map[string]any{
		"full": {
			"complete": true, "author": int64(42), "authors": []any{int64(42), int64(7)}, "committers": []any{int64(8)},
			"pushers": []any{int64(43)},
		},
		"no pushers yet":     {"complete": true, "author": int64(42), "pushers": []any{}},
		"not complete":       {"complete": false, "author": int64(42), "pushers": []any{int64(43)}},
		"no author":          {"complete": true, "pushers": []any{int64(43)}},
		"the author as text": {"complete": true, "author": "42", "pushers": []any{int64(43)}},
		"no pushers":         {"complete": true, "author": int64(42)},
		"a pusher object":    {"complete": true, "author": int64(42), "pushers": []any{map[string]any{"id": int64(43)}}},
		"a negative id":      {"complete": true, "author": int64(42), "pushers": []any{int64(-1)}},
		"authors not a list": {"complete": true, "author": int64(42), "authors": int64(7), "pushers": []any{}},
	} {
		want, ok := domain.GitHubPeople(people)
		l := domain.ListPeople("github.pull.people", people)
		counts := l.Complete && len(l.Gaps) == 0
		if counts != ok {
			t.Errorf("%s: the page counts it %t, the check %t (gaps %v)", name, counts, ok, l.Gaps)
		}
		if ok && !slices.Equal(l.GitHubIDs(), want) {
			t.Errorf("%s: the page lists %v, the check %v", name, l.GitHubIDs(), want)
		}
	}
}

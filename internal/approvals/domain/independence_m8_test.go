// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
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

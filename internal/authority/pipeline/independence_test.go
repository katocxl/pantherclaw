// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"bytes"
	"testing"
	"time"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// peopleRefunds names a charge's people fact as the one an independent
// refund approver must not be in, as pc.github's merge names
// github.pull.people.
func peopleRefunds(raw []byte) []byte {
	raw = bytes.Replace(raw, []byte("      - fact: payments.charge.refundable\n        max_age_seconds: 300\n"),
		[]byte("      - fact: payments.charge.refundable\n        max_age_seconds: 300\n      - fact: payments.charge.people\n        max_age_seconds: 300\n"), 1)
	return bytes.Replace(raw, []byte("      fields: [params.amount, params.reason, target.id]\n"),
		[]byte("      fields: [params.amount, params.reason, target.id]\n      independent_of: payments.charge.people\n"), 1)
}

// TestHR207_AnIndependentApprovalNamesThePeopleFact: the independent
// approval a refund needs carries the people fact its approver must not be
// in, so the approvals side excludes them; when the fact says it could not
// list everyone, the refund cannot be authorized (AUTHORSHIP_UNKNOWN). An
// approval that is not independent names the fact too, and is held up the
// same way (founder decision 2026-10-13).
func TestHR207_AnIndependentApprovalNamesThePeopleFact(t *testing.T) {
	f := newFxWith(t, peopleRefunds, "")
	people := func(complete bool) {
		f.w.PutFact(fdomain.Fact{
			Name: "payments.charge.people", SubjectType: "payments.charge", SubjectID: "ch_1",
			Value:      fdomain.Value{Type: fdomain.TypeObject, Object: map[string]any{"complete": complete, "author": int64(42), "pushers": []any{int64(43)}}},
			ObservedAt: now.Add(-time.Second), RecordedAt: now, ProviderID: f.provider,
		})
	}
	requireApproval := func(independent bool) {
		g := f.newGrant(grantBounds)
		g.Requirements = []gdomain.Requirement{{
			Operations: gdomain.Ops{"payments.refund.create"}, Reason: "REFUNDS_NEED_APPROVAL",
			Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1, Independent: independent},
		}}
		f.w.Grants.Put(g)
		f.run = f.newRun(g.ID)
	}
	people(true)
	requireApproval(true)
	ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	if ev.Decision != adomain.RequireApproval || len(ev.Requirements) != 1 || ev.Requirements[0].IndependentOf != "payments.charge.people" ||
		ev.Hold == nil || ev.Hold.Requirements[0].IndependentOf != "payments.charge.people" {
		t.Fatalf("independent: %s %+v", ev.Decision, ev.Requirements)
	}
	people(false)
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.CannotAuthorize, apdomain.IneligibleAuthorshipUnknown)
	requireApproval(false)
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.CannotAuthorize, apdomain.IneligibleAuthorshipUnknown)
	people(true)
	if ev := f.call(f.run, "create_refund", refund("ch_1", "30.00")); ev.Decision != adomain.RequireApproval ||
		ev.Requirements[0].Independent || ev.Requirements[0].IndependentOf != "payments.charge.people" {
		t.Fatalf("not independent: %s %+v", ev.Decision, ev.Requirements)
	}
}

// TestHR207_ReviewersAndReleaseApproversAreIndependentByRole: HR-207 holds
// per role. A code_reviewer or release_approver requirement is independent
// even when it does not say so; another role is independent only when its
// requirement asks. Every role names the people fact (founder decision
// 2026-10-13), so a fact that could not list everyone leaves the action
// unauthorizable whatever role it asks for.
func TestHR207_ReviewersAndReleaseApproversAreIndependentByRole(t *testing.T) {
	for _, role := range []string{"code_reviewer", "release_approver", "approver"} {
		f := newFxWith(t, peopleRefunds, "")
		people := func(complete bool) {
			f.w.PutFact(fdomain.Fact{
				Name: "payments.charge.people", SubjectType: "payments.charge", SubjectID: "ch_1",
				Value: fdomain.Value{Type: fdomain.TypeObject, Object: map[string]any{
					"complete": complete, "author": int64(42), "pushers": []any{int64(43)},
				}},
				ObservedAt: now.Add(-time.Second), RecordedAt: now, ProviderID: f.provider,
			})
		}
		g := f.newGrant(grantBounds)
		g.Requirements = []gdomain.Requirement{{
			Operations: gdomain.Ops{"payments.refund.create"}, Reason: "REFUNDS_NEED_REVIEW",
			Approval: &pdomain.ApprovalRequirement{Role: role, Count: 1},
		}}
		f.w.Grants.Put(g)
		f.run = f.newRun(g.ID)
		people(true)
		ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
		byRole := role != "approver"
		if ev.Decision != adomain.RequireApproval || len(ev.Requirements) != 1 || ev.Requirements[0].Independent != byRole ||
			ev.Requirements[0].IndependentOf != "payments.charge.people" {
			t.Fatalf("%s: %s %+v", role, ev.Decision, ev.Requirements)
		}
		people(false)
		expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.CannotAuthorize, apdomain.IneligibleAuthorshipUnknown)
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/approvals/adapters/approvalsrpc"
	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// displayed gives a request a rendered display and its hash.
func (f *fx) displayed(request ids.UUID) apdomain.Binding {
	f.t.Helper()
	d := apdomain.Display{V: 1, Kind: "action", Title: "Refund 40.00 USD", Untrusted: apdomain.UntrustedBlock{Label: apdomain.UntrustedLabel}}
	c, err := d.Canonical()
	if err != nil {
		f.t.Fatal(err)
	}
	f.d.AdminExec(f.t, "UPDATE pc.approval_requests SET display = $1::jsonb, display_hash = $2 WHERE id = $3", string(c.Input), c.Hash[:], request)
	return c
}

func orgRole(f *fx, r td.RoleName) td.Binding {
	return td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}
}

// TestT037_ApprovalServiceShowsOnlyWhatTheCallerMaySee: the list and the
// request show a decider their requests (with the scope checked and their
// eligibility) and a stranger nothing; the display comes back canonical
// with its hash; a decline through the API records its codes; a decider's
// note reaches people only.
func TestT037_ApprovalServiceShowsOnlyWhatTheCallerMaySee(t *testing.T) {
	f := newFx(t, 1)
	req := f.request(1)
	display := f.displayed(req)
	h := approvalsrpc.NewApprovals(f.svc)
	bob := f.as(f.bob, orgRole(f, td.RoleApprover))

	list, err := h.ListApprovalRequests(bob, &pantherclawv1.ListApprovalRequestsRequest{WaitingForMe: true})
	if err != nil || len(list.GetRequests()) != 1 || list.GetRequests()[0].GetId() != req.String() ||
		!slices.Equal(list.GetCheckedScopes(), []string{"approver@ORG"}) {
		t.Fatalf("bob's list: %v, %v", list, err)
	}
	if list, err := h.ListApprovalRequests(f.as(f.carol), &pantherclawv1.ListApprovalRequestsRequest{}); err != nil || len(list.GetRequests()) != 0 {
		t.Fatalf("a stranger's list: %v, %v", list, err)
	}
	if _, err := h.GetApprovalRequest(f.as(f.carol), &pantherclawv1.GetApprovalRequestRequest{Id: req.String()}); !errors.Is(err, approvals.ErrNotFound) {
		t.Fatalf("a stranger's get: %v", err)
	}
	got, err := h.GetApprovalRequest(bob, &pantherclawv1.GetApprovalRequestRequest{Id: req.String()})
	if err != nil || string(got.GetDisplay()) != string(display.Input) || got.GetDisplayHash() != display.String() ||
		!got.GetEligibility().GetCanApprove() || !slices.Equal(got.GetEligibility().GetRequirements(), []int32{0}) ||
		got.GetRequest().GetState() != pantherclawv1.ApprovalState_APPROVAL_STATE_PENDING || len(got.GetRequest().GetRequirements()) != 1 {
		t.Fatalf("bob's get: %v, %v", got, err)
	}
	if got, _ := h.GetApprovalRequest(f.as(f.alice), &pantherclawv1.GetApprovalRequestRequest{Id: req.String()}); got.GetEligibility().GetCanRespond() ||
		got.GetEligibility().GetReason() != apdomain.IneligibleLauncher {
		t.Fatalf("the launcher's eligibility: %v", got.GetEligibility())
	}

	d, err := h.DeclineApprovalRequest(bob, &pantherclawv1.DeclineApprovalRequestRequest{
		Id: req.String(), Reason: pantherclawv1.DeclineReason_DECLINE_REASON_WRONG_TARGET,
		Alternative: pantherclawv1.SaferAlternative_SAFER_ALTERNATIVE_ASK_OWNER, Note: "the other charge",
	})
	if err != nil || d.GetRequest().GetState() != pantherclawv1.ApprovalState_APPROVAL_STATE_DECLINED || d.GetRequest().GetEndReason() != "APPROVAL_DECLINED" {
		t.Fatalf("decline: %v, %v", d, err)
	}
	got, _ = h.GetApprovalRequest(bob, &pantherclawv1.GetApprovalRequestRequest{Id: req.String()})
	r := got.GetResponses()
	if len(r) != 1 || r[0].GetDeclineReason() != pantherclawv1.DeclineReason_DECLINE_REASON_WRONG_TARGET ||
		r[0].GetAlternative() != pantherclawv1.SaferAlternative_SAFER_ALTERNATIVE_ASK_OWNER || r[0].GetNote() != "the other charge" {
		t.Fatalf("responses: %v", r)
	}
	service := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()}, Bindings: []td.Binding{orgRole(f, td.RoleAuditor)},
	}, Credential: tenancy.CredAPIKey})
	if got, err := h.GetApprovalRequest(service, &pantherclawv1.GetApprovalRequestRequest{Id: req.String()}); err != nil ||
		len(got.GetResponses()) != 1 || got.GetResponses()[0].GetNote() != "" {
		t.Fatalf("a service account sees a decider's note: %v, %v", got, err)
	}
	if list, _ := h.ListApprovalRequests(bob, &pantherclawv1.ListApprovalRequestsRequest{WaitingForMe: true}); len(list.GetRequests()) != 0 {
		t.Fatal("a declined request is still waiting")
	}
	if list, _ := h.ListApprovalRequests(bob, &pantherclawv1.ListApprovalRequestsRequest{
		States: []pantherclawv1.ApprovalState{pantherclawv1.ApprovalState_APPROVAL_STATE_DECLINED},
	}); len(list.GetRequests()) != 1 {
		t.Fatal("the declined request is not listed by state")
	}
}

// TestHR172_TheAPIProposesAndTakesEvidence: a narrower proposal can be
// simulated through the API, and the run's launcher submits evidence.
func TestHR172_TheAPIProposesAndTakesEvidence(t *testing.T) {
	f := newFx(t, 1)
	req := f.request(1)
	h := approvalsrpc.NewApprovals(f.svc)
	p, err := h.ProposeNarrowerAction(f.as(f.bob), &pantherclawv1.ProposeNarrowerActionRequest{
		Id: req.String(), Params: []byte(`{"amount":{"value":"40.00","currency":"USD"}}`), ValidateOnly: true,
	})
	if err != nil || p.GetSimulatedDecision() != pantherclawv1.Decision_DECISION_ALLOW ||
		p.GetRequest().GetState() != pantherclawv1.ApprovalState_APPROVAL_STATE_PENDING {
		t.Fatalf("proposal: %v, %v", p, err)
	}
	e, err := h.SubmitApprovalEvidence(f.as(f.alice), &pantherclawv1.SubmitApprovalEvidenceRequest{Id: req.String(), Note: "ticket 77"})
	if err != nil || e.GetEvidence().GetId() == "" || e.GetEvidence().GetNote() != "ticket 77" {
		t.Fatalf("evidence: %v, %v", e, err)
	}
}

// TestHR035_TheRequestShowsTheCooldownThatHolds: a person who granted
// themselves Approver a minute ago may decline or ask (no cooldown guards
// those), but GetApprovalRequest and the approval page say they may not
// approve yet, because of the self-grant delay. Checking whether they may
// respond relaxes the cooldowns on a copy only, never on the eligibility
// the reason is read from next.
func TestHR035_TheRequestShowsTheCooldownThatHolds(t *testing.T) {
	f := newFx(t, 1)
	req := f.request(1)
	f.displayed(req)
	f.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by, created_at)
		VALUES ($1, $2, 'approver', $3, 'ORG', $4, now() - interval '1 minute')`, f.org, ids.NewV7(), f.carol.id, "user:"+f.carol.id.String())
	h := approvalsrpc.NewApprovals(f.svc)
	got, err := h.GetApprovalRequest(f.as(f.carol), &pantherclawv1.GetApprovalRequestRequest{Id: req.String()})
	e := got.GetEligibility()
	if err != nil || !e.GetCanRespond() || e.GetCanApprove() || len(e.GetRequirements()) != 0 ||
		e.GetReason() != apdomain.IneligibleSelfGrant {
		t.Fatalf("a fresh self-granted approver's eligibility: %v, %v", e, err)
	}
	v, err := f.svc.View(f.as(f.carol), req)
	if err != nil || !v.MayRespond || v.MayApprove || v.Eligibility.CanApprove || len(v.Eligibility.Requirements) != 0 ||
		v.Eligibility.Reason != apdomain.IneligibleSelfGrant {
		t.Fatalf("the approval page: %v %v %+v, %v", v.MayRespond, v.MayApprove, v.Eligibility, err)
	}
}

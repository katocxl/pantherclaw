// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func waiting(in approvals.Inbox) []ids.UUID {
	var out []ids.UUID
	for _, s := range in.Waiting {
		out = append(out, s.ID)
	}
	return out
}

// TestT037_TheApprovalPageShowsARequestOnlyToThoseWhoMaySeeIt: its eligible
// deciders, the run's launcher and principal, and holders of approval.read
// on the agent's scope path see it; anyone else gets "not found". Only a
// decider may respond, and only one who has not approved yet may approve.
func TestT037_TheApprovalPageShowsARequestOnlyToThoseWhoMaySeeIt(t *testing.T) {
	f := newFx(t, 1)
	req := f.request(2)
	v, err := f.svc.View(f.as(f.bob), req)
	if err != nil || !v.MayRespond || !v.MayApprove || v.State != "PENDING" || v.Request.ID != req {
		t.Fatalf("an approver: %+v, %v", v, err)
	}
	if v, err := f.svc.View(f.as(f.alice), req); err != nil || v.MayRespond || v.MayApprove {
		t.Fatalf("the launcher sees it but may not decide: %v %v, %v", v.MayRespond, v.MayApprove, err)
	}
	if _, err := f.svc.View(f.as(f.carol), req); !errors.Is(err, approvals.ErrNotFound) {
		t.Fatalf("a stranger: %v", err)
	}
	auditor := td.Binding{Role: td.RoleAuditor, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}
	if v, err := f.svc.View(f.as(f.carol, auditor), req); err != nil || v.MayRespond {
		t.Fatalf("an approval.read holder sees it but may not decide: %v, %v", v.MayRespond, err)
	}
	if _, err := f.svc.View(f.as(f.bob), ids.NewV7()); !errors.Is(err, approvals.ErrNotFound) {
		t.Fatalf("an unknown request: %v", err)
	}

	// bob approves (one of two): he may no longer approve, and the request
	// leaves his list but stays on dave's.
	if _, err := f.approve(f.bob, req); err != nil {
		t.Fatal(err)
	}
	v, err = f.svc.View(f.as(f.bob), req)
	if err != nil || v.MayApprove || !v.MayRespond || len(v.Responses) != 1 || v.Responses[0].Kind != "APPROVE" ||
		v.Responses[0].User != f.bob.id || v.Responses[0].Requirement != 0 {
		t.Fatalf("after bob's approval: %+v, %v", v, err)
	}
	approver := td.Binding{Role: td.RoleApprover, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}
	in, err := f.svc.Inbox(f.as(f.bob, approver))
	if err != nil || slices.Contains(waiting(in), req) || len(in.Recent) != 1 || in.Recent[0].Request != req ||
		len(in.Scopes) != 1 || in.Scopes[0] != approver {
		t.Fatalf("bob's list: %+v, %v", in, err)
	}
	in, err = f.svc.Inbox(f.as(f.dave, approver))
	if err != nil || !slices.Equal(waiting(in), []ids.UUID{req}) || in.Waiting[0].Title != "payments.refund.create" ||
		in.Waiting[0].Priority < 1 {
		t.Fatalf("dave's list: %+v, %v", in, err)
	}
	if in, err := f.svc.Inbox(f.as(f.alice)); err != nil || len(in.Waiting) != 0 || len(in.Scopes) != 0 {
		t.Fatalf("the launcher's list: %+v, %v", in, err)
	}
}

// TestHR172_APageResponseRecordsTheBrowserSession: the approval page's
// person responds through their browser session, which the response
// records; a caller with neither kind of human session is refused.
func TestHR172_APageResponseRecordsTheBrowserSession(t *testing.T) {
	f := newFx(t, 1)
	req := f.request(1)
	browser := tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject:    td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.bob.id}},
		Credential: tenancy.CredBrowserSession, Session: f.bob.browser,
	})
	noSession := tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject:    td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.bob.id}},
		Credential: tenancy.CredBrowserSession,
	})
	if _, err := f.svc.Decline(noSession, req, "TOO_RISKY", "", ""); !errors.Is(err, approvals.ErrHumanSession) {
		t.Fatalf("no session: %v", err)
	}
	if _, err := f.svc.Decline(browser, req, "TOO_RISKY", "", ""); err != nil {
		t.Fatal(err)
	}
	got := f.str(`SELECT session_id::text || ' ' || coalesce(cli_session_id::text, 'none') FROM pc.approval_responses WHERE request_id = $1`, req)
	if got != f.bob.browser.String()+" none" {
		t.Fatalf("recorded sessions %q", got)
	}
}

// TestHR034_EvidenceOnThePageIsCleanedAndMarked: evidence is shown without
// bidi and control characters, and a decider's note likewise.
func TestHR034_EvidenceOnThePageIsCleanedAndMarked(t *testing.T) {
	f := newFx(t, 1)
	req := f.request(1)
	rlo := string(rune(0x202e))
	if _, _, err := f.svc.SubmitEvidence(f.as(f.alice), req, "ticket "+rlo+"77"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Decline(f.as(f.bob), req, "TOO_RISKY", "PERSON_PERFORMS", "do it "+rlo+"yourself"); err != nil {
		t.Fatal(err)
	}
	v, err := f.svc.View(f.as(f.bob), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Evidence) != 1 || v.Evidence[0].Note.Text != "ticket 77" || v.Evidence[0].Author != "user:"+f.alice.id.String() {
		t.Fatalf("evidence: %+v", v.Evidence)
	}
	if len(v.Responses) != 1 || strings.Contains(v.Responses[0].Note.Text, rlo) || v.Responses[0].Reason != "TOO_RISKY" ||
		v.Responses[0].Alternative != "PERSON_PERFORMS" {
		t.Fatalf("responses: %+v", v.Responses)
	}
	if v.State != "DECLINED" || v.MayRespond || v.MayApprove {
		t.Fatalf("a declined request: %s %v %v", v.State, v.MayRespond, v.MayApprove)
	}
}

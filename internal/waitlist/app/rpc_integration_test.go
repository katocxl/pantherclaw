// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/waitlistrpc"
	waitlist "github.com/katocxl/pantherclaw/internal/waitlist/app"
)

// TestF626_TheWaitlistListsByPriorityWithItsFilters: entries come by
// priority, then deadline; kinds, priorities, assignment and overdue narrow
// them; the response names the scopes checked.
func TestF626_TheWaitlistListsByPriorityWithItsFilters(t *testing.T) {
	f := newWFx(t)
	h := waitlistrpc.NewWaitlist(waitlist.NewReader(f.p)).WithWriter(f.w)
	recon := f.reconciliation() // priority 1
	var review ids.UUID
	f.tx(func(ctx context.Context, tx db.TenantTx) error {
		var err error
		review, err = pgwaitlist.OpenToolReview(ctx, tx, f.org, ids.NewV7(), "pc.mock-payments", "1.0.0", pgwaitlist.System) // priority 4
		return err
	})
	reader := f.as(f.ben, td.RoleSecurityAdmin, td.RolePolicyPublisher)
	list, err := h.ListWaitlistEntries(reader, &pantherclawv1.ListWaitlistEntriesRequest{})
	if err != nil || len(list.GetEntries()) != 2 || list.GetEntries()[0].GetId() != recon.String() || list.GetEntries()[1].GetId() != review.String() ||
		list.GetEntries()[0].GetKind() != pantherclawv1.WaitlistKind_WAITLIST_KIND_RECONCILIATION || list.GetEntries()[0].GetPriority() != 1 ||
		!slices.Contains(list.GetCheckedScopes(), "security_admin@ORG") {
		t.Fatalf("list: %v, %v", list, err)
	}
	for name, req := range map[string]*pantherclawv1.ListWaitlistEntriesRequest{
		"kind":     {Kinds: []pantherclawv1.WaitlistKind{pantherclawv1.WaitlistKind_WAITLIST_KIND_TOOL_REVIEW}},
		"priority": {Priorities: []int32{4}},
	} {
		if l, err := h.ListWaitlistEntries(reader, req); err != nil || len(l.GetEntries()) != 1 || l.GetEntries()[0].GetId() != review.String() {
			t.Errorf("%s: %v, %v", name, l, err)
		}
	}
	if _, err := h.AssignWaitlistEntry(reader, &pantherclawv1.AssignWaitlistEntryRequest{Id: recon.String()}); err != nil {
		t.Fatal(err)
	}
	if l, _ := h.ListWaitlistEntries(reader, &pantherclawv1.ListWaitlistEntriesRequest{AssignedToMe: true}); len(l.GetEntries()) != 1 ||
		l.GetEntries()[0].GetAssigneeUserId() != f.ben.String() {
		t.Fatalf("assigned to me: %v", l)
	}
	f.overdue(review)
	if l, _ := h.ListWaitlistEntries(reader, &pantherclawv1.ListWaitlistEntriesRequest{Overdue: true}); len(l.GetEntries()) != 1 ||
		l.GetEntries()[0].GetId() != review.String() {
		t.Fatalf("overdue: %v", l)
	}
	if l, _ := h.ListWaitlistEntries(f.as(f.ben), &pantherclawv1.ListWaitlistEntriesRequest{}); len(l.GetEntries()) != 0 || len(l.GetCheckedScopes()) != 0 {
		t.Fatalf("a reader without waitlist.read: %v", l)
	}
}

// TestHR173_SettingsOnlyTightenAndNeedWaitlistManage: settings read back
// with the defaults in effect; an update needs waitlist.manage and stays
// within each bound; zero restores the default.
func TestHR173_SettingsOnlyTightenAndNeedWaitlistManage(t *testing.T) {
	f := newWFx(t)
	h := waitlistrpc.NewWaitlist(waitlist.NewReader(f.p)).WithWriter(f.w)
	admin := f.as(f.ben, td.RoleOrgAdmin)
	got, err := h.GetWaitlistSettings(admin, &pantherclawv1.GetWaitlistSettingsRequest{})
	if err != nil || got.GetSettings().GetHoldDeadlineSeconds() != 3600 || got.GetSettings().GetMaxHoldsPerGrant() != 20 ||
		got.GetSettings().GetMinRoleAgeSeconds() != 86400 || len(got.GetSettings().GetBatchCeilings()) != 0 {
		t.Fatalf("defaults: %v, %v", got, err)
	}
	if _, err := h.GetWaitlistSettings(f.as(f.ben, td.RoleApprover), &pantherclawv1.GetWaitlistSettingsRequest{}); err == nil {
		t.Fatal("an approver read the settings")
	}
	up, err := h.UpdateWaitlistSettings(admin, &pantherclawv1.UpdateWaitlistSettingsRequest{Settings: &pantherclawv1.WaitlistSettings{
		HoldDeadlineSeconds: 1800, MaxHoldsPerGrant: 10, BatchCeilings: map[string]string{"USD": "100.00"},
	}})
	if err != nil || up.GetSettings().GetHoldDeadlineSeconds() != 1800 || up.GetSettings().GetMaxHoldsPerGrant() != 10 ||
		up.GetSettings().GetConsumeWindowSeconds() != 900 || up.GetSettings().GetBatchCeilings()["USD"] != "100.00" ||
		up.GetSettings().GetUpdatedBy() != "user:"+f.ben.String() {
		t.Fatalf("update: %v, %v", up, err)
	}
	for name, st := range map[string]*pantherclawv1.WaitlistSettings{
		"a hold deadline under 5 minutes": {HoldDeadlineSeconds: 60},
		"a shorter cooldown":              {MinRoleAgeSeconds: 3600},
	} {
		if _, err := h.UpdateWaitlistSettings(admin, &pantherclawv1.UpdateWaitlistSettingsRequest{Settings: st}); !errors.Is(err, waitlist.ErrSettingsInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	back, _ := h.UpdateWaitlistSettings(admin, &pantherclawv1.UpdateWaitlistSettingsRequest{Settings: &pantherclawv1.WaitlistSettings{}})
	if back.GetSettings().GetHoldDeadlineSeconds() != 3600 || len(back.GetSettings().GetBatchCeilings()) != 0 {
		t.Fatalf("back to the defaults: %v", back)
	}
}

// TestHR176_AccessRequestsAndChainsThroughTheAPI: the run's launcher files
// an access request and a grant.issue holder dismisses it; a chain set
// through the API reads back.
func TestHR176_AccessRequestsAndChainsThroughTheAPI(t *testing.T) {
	f := newWFx(t)
	h := waitlistrpc.NewWaitlist(waitlist.NewReader(f.p)).WithWriter(f.w)
	e, err := h.RequestAccess(f.as(f.ann), &pantherclawv1.RequestAccessRequest{RunId: f.run.String(), Note: "need refunds"})
	if err != nil || e.GetEntry().GetKind() != pantherclawv1.WaitlistKind_WAITLIST_KIND_ACCESS_REQUEST || e.GetEntry().GetRequestedBy() != "user:"+f.ann.String() {
		t.Fatalf("request: %v, %v", e, err)
	}
	d, err := h.DismissAccessRequest(f.as(f.ben, td.RoleGrantIssuer), &pantherclawv1.DismissAccessRequestRequest{Id: e.GetEntry().GetId(), Reason: "no"})
	if err != nil || d.GetEntry().GetState() != pantherclawv1.WaitlistState_WAITLIST_STATE_REJECTED {
		t.Fatalf("dismiss: %v, %v", d, err)
	}
	set, err := h.SetEscalationChain(f.as(f.ben, td.RoleOrgAdmin), &pantherclawv1.SetEscalationChainRequest{Steps: []*pantherclawv1.EscalationStep{
		{AtPercent: 0, Scope: pantherclawv1.EscalationScope_ESCALATION_SCOPE_NEAREST, NotifyChannels: true},
		{AtPercent: 60, Scope: pantherclawv1.EscalationScope_ESCALATION_SCOPE_ORG, Remind: true, NotifyOwners: true},
	}})
	if err != nil || set.GetChain().GetRevision() != 1 {
		t.Fatalf("set chain: %v, %v", set, err)
	}
	got, err := h.GetEscalationChain(f.as(f.ben, td.RoleApprover), &pantherclawv1.GetEscalationChainRequest{})
	if err != nil || len(got.GetChain().GetSteps()) != 2 || got.GetChain().GetSteps()[1].GetScope() != pantherclawv1.EscalationScope_ESCALATION_SCOPE_ORG ||
		!got.GetChain().GetSteps()[1].GetNotifyOwners() {
		t.Fatalf("get chain: %v, %v", got, err)
	}
}

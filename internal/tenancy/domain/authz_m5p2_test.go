// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestT043_OrgAdminStaysOutOfApprovalsAndRestorations: administration never
// approves, sees approval content or restores a suspended agent (F583, G0
// M5 part 2): approval.respond and agent.restore stay human only, and only
// their own roles hold them.
func TestT043_OrgAdminStaysOutOfApprovalsAndRestorations(t *testing.T) {
	tr := newTree()
	admin := user(tr.org, bind(domain.RoleOrgAdmin, domain.ScopeOrg, tr.org.UUID()))
	for _, p := range []domain.Permission{domain.PermApprovalRespond, domain.PermApprovalRead, domain.PermAgentRestore} {
		if admin.CanAnywhere(p) {
			t.Errorf("Org Admin holds %s", p)
		}
	}
	if !admin.CanAnywhere(domain.PermWaitlistManage) {
		t.Error("Org Admin cannot manage the waitlist's escalation and settings")
	}
	for _, p := range []domain.Permission{domain.PermApprovalRespond, domain.PermAgentRestore} {
		if !p.HumanOnly() || p.APIKeyScopable() {
			t.Errorf("%s is not human only", p)
		}
	}
	if err := domain.CheckAPIKeyScopes([]domain.Permission{domain.PermAgentRestore}); !errors.Is(err, domain.ErrHumanOnlyScope) {
		t.Errorf("API key scope agent.restore: %v", err)
	}
	holders := func(p domain.Permission) []domain.RoleName {
		var out []domain.RoleName
		for _, r := range domain.Roles() {
			if r.Has(p) {
				out = append(out, r.Name)
			}
		}
		slices.Sort(out)
		return out
	}
	want := map[domain.Permission][]domain.RoleName{
		domain.PermAgentRestore:   {domain.RoleResponder, domain.RoleSecurityAdmin},
		domain.PermApprovalRead:   {domain.RoleAgentOwner, domain.RoleApprover, domain.RoleAuditor, domain.RoleSecurityAdmin},
		domain.PermWaitlistManage: {domain.RoleOrgAdmin, domain.RoleSecurityAdmin},
	}
	for p, roles := range want {
		slices.Sort(roles)
		if got := holders(p); !slices.Equal(got, roles) {
			t.Errorf("%s is held by %v, want %v", p, got, roles)
		}
	}
	// waitlist.read reaches everyone entries are routed to.
	for _, r := range []domain.RoleName{
		domain.RoleApprover, domain.RoleGrantIssuer, domain.RolePolicyPublisher, domain.RoleResponder, domain.RoleReconciler,
	} {
		role, _ := domain.LookupRole(r)
		if !role.Has(domain.PermWaitlistRead) {
			t.Errorf("%s cannot read the waitlist entries routed to it", r)
		}
	}
	// A service account bound to every role still cannot restore or approve.
	var bs []domain.Binding
	for _, r := range domain.Roles() {
		bs = append(bs, bind(r.Name, domain.ScopeOrg, tr.org.UUID()))
	}
	sa := serviceAccount(tr.org, bs...)
	if sa.CanAnywhere(domain.PermAgentRestore) || sa.CanAnywhere(domain.PermApprovalRespond) {
		t.Error("a service account can restore agents or approve")
	}
	if !sa.CanAnywhere(domain.PermApprovalRead) {
		t.Error("approval.read is not human only")
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestM11_AutomationPermissionsAndRoles: the M11 part 2 permissions of D12
// and the roles that hold them, exactly.
func TestM11_AutomationPermissionsAndRoles(t *testing.T) {
	want := map[domain.Permission][]domain.RoleName{
		domain.PermAutomationRead: {
			domain.RoleAuditor, domain.RoleAutomationAuthor, domain.RoleAutomationOperator, domain.RoleAutomationPublisher,
			domain.RoleOrgAdmin, domain.RoleResponder, domain.RoleSecurityAdmin, domain.RoleViewer,
		},
		domain.PermAutomationManage:          {domain.RoleAutomationAuthor},
		domain.PermAutomationEndpointsManage: {domain.RoleAutomationAuthor},
		domain.PermAutomationPublish:         {domain.RoleAutomationPublisher},
		domain.PermAutomationApprove:         {domain.RoleAutomationOperator, domain.RoleAutomationPublisher},
		domain.PermAutomationRun:             {domain.RoleAutomationOperator},
		domain.PermAgentPromote:              {domain.RoleFleetManager},
		domain.PermCohortManage:              {domain.RoleFleetManager},
		domain.PermProtectedChangeManage:     {domain.RoleSecurityAdmin},
		domain.PermPublisherCompromise:       {domain.RoleSecurityAdmin},
	}
	for p, roles := range want {
		if !p.Known() || !p.Declarable() {
			t.Errorf("%s is not in the catalog", p)
		}
		roles = slices.Clone(roles)
		slices.Sort(roles)
		if got := holders(p); !slices.Equal(got, roles) {
			t.Errorf("%s is held by %v, want %v", p, got, roles)
		}
	}
}

// TestM11_AutomationHumanOnly: everything but automation.read is for
// people only (HR-279); Org Admin and Agent Owner stay bindable to service
// accounts.
func TestM11_AutomationHumanOnly(t *testing.T) {
	for _, p := range []domain.Permission{
		domain.PermAutomationManage, domain.PermAutomationPublish, domain.PermAutomationRun, domain.PermAutomationApprove,
		domain.PermAutomationEndpointsManage, domain.PermAgentPromote, domain.PermCohortManage,
		domain.PermProtectedChangeManage, domain.PermPublisherCompromise,
	} {
		if !p.HumanOnly() || p.APIKeyScopable() {
			t.Errorf("%s: human only %v, API-key scopable %v; want true, false", p, p.HumanOnly(), p.APIKeyScopable())
		}
	}
	if domain.PermAutomationRead.HumanOnly() {
		t.Error("automation.read is human only")
	}
	for _, r := range []domain.RoleName{domain.RoleOrgAdmin, domain.RoleAgentOwner, domain.RoleViewer} {
		if _, err := domain.CheckBindable(r, domain.KindServiceAccount, domain.ScopeOrg); err != nil && r == domain.RoleOrgAdmin {
			t.Errorf("%s is no longer bindable to service accounts: %v", r, err)
		}
		if role, _ := domain.LookupRole(r); role.HumanOnly() {
			t.Errorf("%s became human only", r)
		}
	}
	for _, r := range []domain.RoleName{
		domain.RoleAutomationAuthor, domain.RoleAutomationPublisher, domain.RoleAutomationOperator, domain.RoleFleetManager,
	} {
		if role, ok := domain.LookupRole(r); !ok || !role.HumanOnly() {
			t.Errorf("%s: found %v, human only %v; want a human-only role", r, ok, role.HumanOnly())
		}
	}
}

// TestHR272_NoRoleAuthorsAndPublishesAutomations: whoever writes an
// automation never confirms its enabling through the same role (HR-272).
func TestHR272_NoRoleAuthorsAndPublishesAutomations(t *testing.T) {
	for _, r := range domain.Roles() {
		if r.Has(domain.PermAutomationManage) && r.Has(domain.PermAutomationPublish) {
			t.Errorf("role %s holds both automation.manage and automation.publish", r.Name)
		}
	}
}

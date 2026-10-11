// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR207_ReleaseRolesApproveAndOnlyPeopleSetWindows: the Code Reviewer
// and the Release Approver hold approval.respond, so a requirement can
// name them, and are bound only to people. Change windows are set by the
// Security Admin, a person: Org Admin does not hold release.window.manage,
// because a human-only permission would keep it from service accounts.
func TestHR207_ReleaseRolesApproveAndOnlyPeopleSetWindows(t *testing.T) {
	for _, r := range []domain.RoleName{domain.RoleCodeReviewer, domain.RoleReleaseApprover} {
		role, ok := domain.LookupRole(r)
		if !ok || !role.Has(domain.PermApprovalRespond) || !role.Has(domain.PermApprovalRead) {
			t.Errorf("%s: %+v", r, role.Permissions)
		}
		if _, err := domain.CheckBindable(r, domain.KindServiceAccount, domain.ScopeOrg); err == nil {
			t.Errorf("%s is bindable to a service account", r)
		}
	}
	p := domain.PermReleaseWindowManage
	if !p.Known() || !p.HumanOnly() || !slices.Equal(holders(p), []domain.RoleName{domain.RoleSecurityAdmin}) {
		t.Fatalf("%s: known %v, human only %v, held by %v", p, p.Known(), p.HumanOnly(), holders(p))
	}
}

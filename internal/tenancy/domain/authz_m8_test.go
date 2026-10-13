// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR207_ReleaseRolesApproveAndOnlyPeopleSetWindows: the Code Reviewer
// and the Release Approver hold approval.respond, so a requirement can
// name them, and are bound only to people, at a team or an environment
// (M8.md), never across the organization or a business unit. Change
// windows are set by the Security Admin, a person: Org Admin does not hold
// release.window.manage, because a human-only permission would keep it
// from service accounts.
func TestHR207_ReleaseRolesApproveAndOnlyPeopleSetWindows(t *testing.T) {
	for _, r := range []domain.RoleName{domain.RoleCodeReviewer, domain.RoleReleaseApprover} {
		role, ok := domain.LookupRole(r)
		if !ok || !role.Has(domain.PermApprovalRespond) || !role.Has(domain.PermApprovalRead) {
			t.Errorf("%s: %+v", r, role.Permissions)
		}
		for _, s := range []domain.ScopeType{domain.ScopeTeam, domain.ScopeEnvironment} {
			if _, err := domain.CheckBindable(r, domain.KindServiceAccount, s); !errors.Is(err, domain.ErrHumanOnlyRole) {
				t.Errorf("%s is bindable to a service account at %s: %v", r, s, err)
			}
			if _, err := domain.CheckBindable(r, domain.KindUser, s); err != nil {
				t.Errorf("%s is not bindable to a person at %s: %v", r, s, err)
			}
		}
		for _, s := range []domain.ScopeType{domain.ScopeOrg, domain.ScopeBusinessUnit} {
			if _, err := domain.CheckBindable(r, domain.KindUser, s); !errors.Is(err, domain.ErrScopeNotAllowed) {
				t.Errorf("%s is bindable at %s: %v", r, s, err)
			}
		}
	}
	p := domain.PermReleaseWindowManage
	if !p.Known() || !p.HumanOnly() || !slices.Equal(holders(p), []domain.RoleName{domain.RoleSecurityAdmin}) {
		t.Fatalf("%s: known %v, human only %v, held by %v", p, p.Known(), p.HumanOnly(), holders(p))
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestM9_CoveragePermissionsAndRoles: the coverage permissions of G0 M9
// track A and the roles that hold them, exactly. Org Admin reads coverage
// but does not manage it: a human-only permission would make Org Admin a
// human-only role (HR-183).
func TestM9_CoveragePermissionsAndRoles(t *testing.T) {
	want := map[domain.Permission][]domain.RoleName{
		domain.PermCoverageRead: {
			domain.RoleAgentOwner, domain.RoleAuditor, domain.RoleDeveloper, domain.RoleOrgAdmin, domain.RoleResponder,
			domain.RoleSecurityAdmin,
		},
		domain.PermCoverageManage:   {domain.RoleSecurityAdmin},
		domain.PermCoverageReassess: {domain.RoleAgentOwner, domain.RoleSecurityAdmin},
	}
	for p, roles := range want {
		if !p.Known() || !p.Declarable() {
			t.Errorf("%s is not in the catalog", p)
		}
		slices.Sort(roles)
		if got := holders(p); !slices.Equal(got, roles) {
			t.Errorf("%s is held by %v, want %v", p, got, roles)
		}
	}
}

// TestHR212_OnlyPeopleExcludeFromCoverage: excluding a route from coverage
// or acknowledging a finding weakens the claim, so coverage.manage is human
// only: no API key or service account can carry it.
func TestHR212_OnlyPeopleExcludeFromCoverage(t *testing.T) {
	if p := domain.PermCoverageManage; !p.HumanOnly() || p.APIKeyScopable() {
		t.Errorf("%s: human only %v, API-key scopable %v; want true, false", p, p.HumanOnly(), p.APIKeyScopable())
	}
	for _, p := range []domain.Permission{domain.PermCoverageRead, domain.PermCoverageReassess} {
		if p.HumanOnly() {
			t.Errorf("%s is human only; services read and refresh coverage too", p)
		}
	}
}

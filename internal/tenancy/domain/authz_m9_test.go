// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestM9_CoveragePermissionsAndRoles: the coverage permissions of G0 M9
// track A and the roles that hold them, exactly.
func TestM9_CoveragePermissionsAndRoles(t *testing.T) {
	want := map[domain.Permission][]domain.RoleName{
		domain.PermCoverageRead: {
			domain.RoleAgentOwner, domain.RoleAuditor, domain.RoleEmergency, domain.RoleGatewayAdmin, domain.RoleOrgAdmin,
			domain.RoleSecurityAdmin,
		},
		domain.PermCoverageManage:  {domain.RoleGatewayAdmin, domain.RoleSecurityAdmin},
		domain.PermCoverageExclude: {domain.RoleSecurityAdmin},
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
// weakens the claim, so coverage.exclude (and coverage.manage, which
// dismisses findings) is human only: no API key can carry it.
func TestHR212_OnlyPeopleExcludeFromCoverage(t *testing.T) {
	for _, p := range []domain.Permission{domain.PermCoverageExclude, domain.PermCoverageManage} {
		if !p.HumanOnly() || p.APIKeyScopable() {
			t.Errorf("%s: human only %v, API-key scopable %v; want true, false", p, p.HumanOnly(), p.APIKeyScopable())
		}
	}
	if domain.PermCoverageRead.HumanOnly() {
		t.Error("coverage.read is human only; services read coverage too")
	}
}

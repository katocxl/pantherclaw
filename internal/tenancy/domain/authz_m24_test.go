// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestM24_PermissionsAndRoles: the M24 permissions of G0 M24 D222 and D236
// and the roles that hold them, exactly. None is human only in the catalog;
// the catalogue service refuses any caller but a person where D222 says so.
func TestM24_PermissionsAndRoles(t *testing.T) {
	want := map[domain.Permission][]domain.RoleName{
		domain.PermCatalogRead:     {domain.RoleAuditor, domain.RoleOrgAdmin, domain.RoleSecurityAdmin},
		domain.PermCatalogManage:   {domain.RoleSecurityAdmin},
		domain.PermAgentScanSubmit: {domain.RoleScanner},
	}
	for p, roles := range want {
		if !p.Known() || !p.Declarable() || p.HumanOnly() {
			t.Errorf("%s: known=%v declarable=%v human-only=%v", p, p.Known(), p.Declarable(), p.HumanOnly())
		}
		var got []domain.RoleName
		for _, r := range domain.Roles() {
			if r.Has(p) {
				got = append(got, r.Name)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, roles) {
			t.Errorf("%s: held by %v, want %v", p, got, roles)
		}
	}
}

// TestM24_ScannerRole: beyond the hierarchy reads every role holds
// (TestRoleCatalogIsWellFormed), the Scanner role holds agent.scan.submit
// alone, and binds only to service accounts.
func TestM24_ScannerRole(t *testing.T) {
	r, ok := domain.LookupRole(domain.RoleScanner)
	if !ok {
		t.Fatal("no Scanner role")
	}
	want := []domain.Permission{
		domain.PermOrgRead, domain.PermBusinessUnitRead, domain.PermTeamRead, domain.PermEnvironmentRead, domain.PermAgentScanSubmit,
	}
	if !slices.Equal(r.Permissions, want) {
		t.Errorf("Scanner holds %v", r.Permissions)
	}
	if !r.ServiceOnly {
		t.Error("Scanner can be bound to a person")
	}
	if _, err := domain.CheckBindable(domain.RoleScanner, domain.KindServiceAccount, domain.ScopeTeam); err != nil {
		t.Errorf("Scanner on a service account: %v", err)
	}
	if _, err := domain.CheckBindable(domain.RoleScanner, domain.KindUser, domain.ScopeTeam); err == nil {
		t.Error("Scanner bound to a user")
	}
}

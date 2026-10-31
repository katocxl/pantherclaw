// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestM23_PermissionsAndRoles: the M23 permissions of G0 M23 D103 and the
// roles that hold them, exactly. hub.install is not in the human-only
// catalog, because Org Admin stays bindable to service accounts; the Hub
// service refuses any caller but a person.
func TestM23_PermissionsAndRoles(t *testing.T) {
	want := map[domain.Permission][]domain.RoleName{
		domain.PermHubRead: {
			domain.RoleAuditor, domain.RoleAutomationAuthor, domain.RoleOrgAdmin, domain.RolePolicyAuthor, domain.RoleSecurityAdmin,
		},
		domain.PermHubInstall: {
			domain.RoleAutomationAuthor, domain.RoleOrgAdmin, domain.RolePolicyAuthor, domain.RoleSecurityAdmin,
		},
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

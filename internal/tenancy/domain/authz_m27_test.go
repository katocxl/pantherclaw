// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestM27_PermissionsAndRoles: the M27 permission of G0 M27 D501 and D502
// and the roles that hold it, exactly: every role that reads incidents, and
// those who see approval requests, beside which the context shows. It is
// not human only: a service account bound to such a role reads in scope.
// Covers: F930, F934
func TestM27_PermissionsAndRoles(t *testing.T) {
	want := map[domain.Permission][]domain.RoleName{
		domain.PermBehaviorRead: {
			domain.RoleAgentOwner, domain.RoleApprover, domain.RoleAuditor, domain.RoleOrgAdmin,
			domain.RoleResponder, domain.RoleSecurityAdmin,
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
		slices.Sort(roles)
		if !slices.Equal(got, roles) {
			t.Errorf("%s: held by %v, want %v", p, got, roles)
		}
	}
}

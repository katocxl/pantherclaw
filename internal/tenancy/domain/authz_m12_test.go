// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestM12_RedteamPermissionsAndRoles: redteam.run mirrors sandbox.run (the
// Agent Owner and Developer roles) and redteam.read mirrors coverage.read.
// Neither is human only: CI service accounts run the regression gate
// (HR-226).
func TestM12_RedteamPermissionsAndRoles(t *testing.T) {
	want := map[domain.Permission][]domain.RoleName{
		domain.PermRedteamRun: {domain.RoleAgentOwner, domain.RoleDeveloper},
		domain.PermRedteamRead: {
			domain.RoleAgentOwner, domain.RoleAuditor, domain.RoleDeveloper, domain.RoleOrgAdmin, domain.RoleResponder,
			domain.RoleSecurityAdmin,
		},
	}
	for p, roles := range want {
		if !p.Known() || !p.Declarable() || p.HumanOnly() || !p.APIKeyScopable() {
			t.Errorf("%s: known %v, declarable %v, human only %v", p, p.Known(), p.Declarable(), p.HumanOnly())
		}
		slices.Sort(roles)
		if got := holders(p); !slices.Equal(got, roles) {
			t.Errorf("%s is held by %v, want %v", p, got, roles)
		}
	}
}

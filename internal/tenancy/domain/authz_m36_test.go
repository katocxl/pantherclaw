// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR786_OTLPRolesFollowSIEM: otlp.read is held by Org Admin, Security
// Admin and Auditor; otlp.manage is held by Security Admin and is for
// people only.
// Covers: HR-786, F1061
func TestHR786_OTLPRolesFollowSIEM(t *testing.T) {
	want := map[domain.Permission][]domain.RoleName{
		domain.PermOTLPRead:   {domain.RoleAuditor, domain.RoleOrgAdmin, domain.RoleSecurityAdmin},
		domain.PermOTLPManage: {domain.RoleSecurityAdmin},
	}
	for p, roles := range want {
		if !p.Known() || !p.Declarable() {
			t.Errorf("%s: known=%v declarable=%v", p, p.Known(), p.Declarable())
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
	if domain.PermOTLPRead.HumanOnly() || !domain.PermOTLPManage.HumanOnly() {
		t.Fatal("otlp.manage is for people only and otlp.read is not")
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR647_ContentPermissions: the content permissions and the roles that
// hold them, exactly; content.manage is for people only.
//
// Covers: F936
func TestHR647_ContentPermissions(t *testing.T) {
	want := map[domain.Permission][]domain.RoleName{
		domain.PermContentRead:   {domain.RoleAuditor, domain.RoleOrgAdmin, domain.RoleSecurityAdmin},
		domain.PermContentManage: {domain.RoleSecurityAdmin},
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
	if domain.PermContentRead.HumanOnly() || !domain.PermContentManage.HumanOnly() {
		t.Error("content.manage is human only and content.read is not")
	}
}

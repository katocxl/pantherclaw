// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR387_SupportRolesOnlyReadAndAreNeverBindable: a support session's
// roles hold reads only, never restricted evidence unless the grant's
// scope adds it, never a service-only permission; no binding can name
// them; and only a support subject holds them.
func TestHR387_SupportRolesOnlyReadAndAreNeverBindable(t *testing.T) {
	for _, ev := range []bool{false, true} {
		ps := domain.SupportReadOnlyPermissions(ev)
		if len(ps) < 20 {
			t.Fatalf("support reads = %d permissions", len(ps))
		}
		hasRestricted := false
		for _, p := range ps {
			if !strings.HasSuffix(string(p), ".read") && p != domain.PermEvidenceReadRestricted {
				t.Errorf("support role holds %s", p)
			}
			if p.ServiceOnly() || p.Gateway() || !p.Known() {
				t.Errorf("support role holds %s", p)
			}
			hasRestricted = hasRestricted || p == domain.PermEvidenceReadRestricted
		}
		if hasRestricted != ev {
			t.Errorf("evidence scope %v: restricted evidence %v", ev, hasRestricted)
		}
	}
	for _, n := range domain.SupportRoleNames(true) {
		if _, ok := domain.LookupRole(n); ok {
			t.Errorf("%s is bindable", n)
		}
		for _, r := range domain.Roles() {
			if r.Name == n {
				t.Errorf("%s is listed among the roles", n)
			}
		}
	}
	org := ids.New[ids.Org]()
	bs := []domain.Binding{
		{Role: domain.RoleSupportReadOnly, Scope: domain.Scope{Type: domain.ScopeOrg, ID: org.UUID()}},
		{Role: domain.RoleSupportEvidence, Scope: domain.Scope{Type: domain.ScopeOrg, ID: org.UUID()}},
	}
	sup := domain.Subject{Org: org, Principal: domain.PrincipalRef{Kind: domain.KindSupport, ID: ids.NewV7()}, Bindings: bs}
	user := domain.Subject{Org: org, Principal: domain.PrincipalRef{Kind: domain.KindUser, ID: ids.NewV7()}, Bindings: bs}
	if !sup.Can(domain.PermEvidenceReadRestricted, domain.OrgPath(org)) || !sup.Can(domain.PermAuditRead, domain.OrgPath(org)) {
		t.Error("a support subject lacks its roles' reads")
	}
	if sup.Human() || !sup.Person() {
		t.Error("a support subject is a person only for human-only checks")
	}
	for _, p := range []domain.Permission{
		domain.PermUserManage, domain.PermApprovalRespond, domain.PermCredentialSeal,
		domain.PermEvidenceExport, domain.PermSupportManage, domain.PermContainmentKillSwitch,
	} {
		if sup.CanAnywhere(p) {
			t.Errorf("a support subject holds %s", p)
		}
	}
	if user.CanAnywhere(domain.PermAuditRead) {
		t.Error("a user holds an internal support role through a forged binding")
	}
}

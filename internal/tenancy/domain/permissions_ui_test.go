// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestUIPermissionGrantsFollowD35: every role a person holds reads the
// plan except the two single-job roles; onboarding progress belongs to the
// four roles that run onboarding; service-only roles get neither; and the
// account permissions are on no role at all.
func TestUIPermissionGrantsFollowD35(t *testing.T) {
	noPlan := []domain.RoleName{domain.RoleRunLauncher, domain.RoleFactProvider}
	onboarding := []domain.RoleName{domain.RoleOrgAdmin, domain.RoleSecurityAdmin, domain.RoleAgentOwner, domain.RoleDeveloper}
	for _, r := range domain.Roles() {
		wantPlan := !r.ServiceOnly && !slices.Contains(noPlan, r.Name)
		if r.Has(domain.PermEntitlementsRead) != wantPlan {
			t.Errorf("%s: entitlements.read = %v, want %v", r.Name, !wantPlan, wantPlan)
		}
		if r.Has(domain.PermOnboardingRead) != slices.Contains(onboarding, r.Name) {
			t.Errorf("%s: onboarding.read wrong", r.Name)
		}
		if r.Has(domain.PermBillingManage) != (r.Name == domain.RoleOrgAdmin) {
			t.Errorf("%s: billing.manage wrong (D70: Org Admin only)", r.Name)
		}
		for _, p := range []domain.Permission{domain.PermOrgsCreate, domain.PermOrgsListMine, domain.PermInvitationsAccept} {
			if r.Has(p) {
				t.Errorf("%s holds the account permission %s", r.Name, p)
			}
		}
	}
	for _, p := range []domain.Permission{domain.PermOrgsCreate, domain.PermOrgsListMine, domain.PermInvitationsAccept} {
		if p.Known() || !p.Declarable() {
			t.Errorf("%s: known=%v declarable=%v, want a declarable-only requirement", p, p.Known(), p.Declarable())
		}
	}
	for _, p := range []domain.Permission{domain.PermEntitlementsRead, domain.PermOnboardingRead} {
		if !p.Known() || p.HumanOnly() {
			t.Errorf("%s: known=%v human-only=%v", p, p.Known(), p.HumanOnly())
		}
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestM10_ReflexPermissionsAndRoles: the Reflex permissions of G0 M10 D4
// and the roles that hold them, exactly.
func TestM10_ReflexPermissionsAndRoles(t *testing.T) {
	reads := []domain.RoleName{domain.RoleAuditor, domain.RoleOrgAdmin, domain.RoleResponder, domain.RoleSecurityAdmin}
	want := map[domain.Permission][]domain.RoleName{
		domain.PermDetectionRead:   reads,
		domain.PermDetectionManage: {domain.RoleSecurityAdmin},
		domain.PermIncidentRead: {
			domain.RoleAuditor, domain.RoleOrgAdmin, domain.RoleResponder, domain.RoleSOARIntegration,
			domain.RoleSecurityAdmin, domain.RoleViewer,
		},
		domain.PermIncidentManage:  {domain.RoleResponder, domain.RoleSecurityAdmin},
		domain.PermCaseRead:        reads,
		domain.PermCaseManage:      {domain.RoleResponder, domain.RoleSecurityAdmin},
		domain.PermExposureRead:    reads,
		domain.PermPostureRead:     reads,
		domain.PermPostureManage:   {domain.RoleResponder, domain.RoleSecurityAdmin},
		domain.PermOperationsRead:  {domain.RoleAuditor, domain.RoleOrgAdmin, domain.RoleResponder, domain.RoleSecurityAdmin, domain.RoleViewer},
		domain.PermSearchRead:      reads,
		domain.PermSIEMRead:        reads,
		domain.PermSIEMManage:      {domain.RoleSecurityAdmin},
		domain.PermSignalsRead:     reads,
		domain.PermSignalsManage:   {domain.RoleSecurityAdmin},
		domain.PermResponseRequest: {domain.RoleSOARIntegration},
	}
	for p, roles := range want {
		if !p.Known() || !p.Declarable() {
			t.Errorf("%s is not in the catalog", p)
		}
		roles = slices.Clone(roles)
		slices.Sort(roles)
		if got := holders(p); !slices.Equal(got, roles) {
			t.Errorf("%s is held by %v, want %v", p, got, roles)
		}
	}
}

// TestM10_ReflexHumanOnly: managing detections, incidents, cases, export
// destinations and Shared Signals transmitters is for people only; the
// reads and SOAR requests are not.
func TestM10_ReflexHumanOnly(t *testing.T) {
	human := []domain.Permission{
		domain.PermDetectionManage, domain.PermSIEMManage, domain.PermSignalsManage, domain.PermCaseManage, domain.PermIncidentManage,
	}
	for _, p := range human {
		if !p.HumanOnly() || p.APIKeyScopable() {
			t.Errorf("%s: human only %v, API-key scopable %v; want true, false", p, p.HumanOnly(), p.APIKeyScopable())
		}
	}
	for _, p := range []domain.Permission{
		domain.PermDetectionRead, domain.PermIncidentRead, domain.PermCaseRead, domain.PermExposureRead, domain.PermPostureRead,
		domain.PermPostureManage, domain.PermOperationsRead, domain.PermSearchRead, domain.PermSIEMRead, domain.PermSignalsRead,
		domain.PermResponseRequest,
	} {
		if p.HumanOnly() {
			t.Errorf("%s is human only", p)
		}
	}
	// Org Admin and Viewer stay bindable to service accounts.
	for _, r := range []domain.RoleName{domain.RoleOrgAdmin, domain.RoleViewer, domain.RoleAuditor} {
		if role, _ := domain.LookupRole(r); role.HumanOnly() && r != domain.RoleAuditor {
			t.Errorf("%s became human only", r)
		}
	}
}

// TestM10_SOARIntegrationIsServiceOnly: the SOAR role binds only to
// service accounts, never to a person, and holds no human-only permission.
func TestM10_SOARIntegrationIsServiceOnly(t *testing.T) {
	if _, err := domain.CheckBindable(domain.RoleSOARIntegration, domain.KindUser, domain.ScopeOrg); !errors.Is(err, domain.ErrServiceOnlyRole) {
		t.Errorf("binding soar_integration to a user: %v, want SERVICE_ONLY_ROLE", err)
	}
	if _, err := domain.CheckBindable(domain.RoleSOARIntegration, domain.KindServiceAccount, domain.ScopeOrg); err != nil {
		t.Errorf("binding soar_integration to a service account: %v", err)
	}
	r, _ := domain.LookupRole(domain.RoleSOARIntegration)
	if r.Has(domain.PermContainmentKillSwitch) || r.Has(domain.PermAgentRestore) {
		t.Error("soar_integration can engage the kill switch or restore")
	}
}

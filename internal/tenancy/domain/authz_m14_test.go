// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestM14_PermissionsAndRoles: the M14 permissions of G0 M14 D5 and the
// roles that hold them, exactly.
func TestM14_PermissionsAndRoles(t *testing.T) {
	want := map[domain.Permission][]domain.RoleName{
		domain.PermAuthZENEvaluate:        {domain.RoleEnforcementPoint},
		domain.PermEnforcementPointManage: {domain.RoleOrgAdmin, domain.RoleSecurityAdmin},
		domain.PermA2APeerRunRead:         {domain.RoleAuditor, domain.RoleOrgAdmin, domain.RoleSecurityAdmin},
	}
	for p, roles := range want {
		if !p.Known() {
			t.Errorf("%s is not in the catalog", p)
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
	r, ok := domain.LookupRole(domain.RoleEnforcementPoint)
	if !ok || !r.ServiceOnly || !slices.Equal(r.Scopes, []domain.ScopeType{domain.ScopeOrg}) {
		t.Fatalf("enforcement point role: %+v", r)
	}
}

// TestM14_AuthZENEvaluateIsForServiceAccountsOnly: a person never holds
// authzen.evaluate, whatever their bindings, and cannot be bound to the
// Enforcement Point role; a service account bound to it holds it at org
// scope (G0 M14 D5).
func TestM14_AuthZENEvaluateIsForServiceAccountsOnly(t *testing.T) {
	if _, err := domain.CheckBindable(domain.RoleEnforcementPoint, domain.KindUser, domain.ScopeOrg); !errors.Is(err, domain.ErrServiceOnlyRole) {
		t.Fatalf("a person bound to Enforcement Point: %v", err)
	}
	if _, err := domain.CheckBindable(domain.RoleEnforcementPoint, domain.KindServiceAccount, domain.ScopeTeam); !errors.Is(err, domain.ErrScopeNotAllowed) {
		t.Fatalf("at team scope: %v", err)
	}
	if _, err := domain.CheckBindable(domain.RoleEnforcementPoint, domain.KindServiceAccount, domain.ScopeOrg); err != nil {
		t.Fatalf("a service account: %v", err)
	}
	org := ids.New[ids.Org]()
	binding := []domain.Binding{{Role: domain.RoleEnforcementPoint, Scope: domain.Scope{Type: domain.ScopeOrg, ID: org.UUID()}}}
	sa := domain.Subject{Org: org, Principal: domain.PrincipalRef{Kind: domain.KindServiceAccount, ID: ids.NewV7()}, Bindings: binding}
	person := domain.Subject{Org: org, Principal: domain.PrincipalRef{Kind: domain.KindUser, ID: ids.NewV7()}, Bindings: binding}
	if !sa.Can(domain.PermAuthZENEvaluate, domain.OrgPath(org)) {
		t.Fatal("the service account cannot evaluate")
	}
	if person.Can(domain.PermAuthZENEvaluate, domain.OrgPath(org)) || person.CanAnywhere(domain.PermAuthZENEvaluate) {
		t.Fatal("a person holds authzen.evaluate")
	}
}

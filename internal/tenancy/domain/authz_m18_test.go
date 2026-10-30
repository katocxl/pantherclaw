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

// TestM18_ScopeAdminRole: the Scope Admin role of G0 M18 D152 holds
// role.bind, role.read and user.read plus the hierarchy reads, and binds
// only at business unit, team or environment scope, never at the org.
//
// Covers: F584
func TestM18_ScopeAdminRole(t *testing.T) {
	r, ok := domain.LookupRole(domain.RoleScopeAdmin)
	if !ok {
		t.Fatal("no Scope Admin role")
	}
	want := []domain.Permission{
		domain.PermOrgRead, domain.PermBusinessUnitRead, domain.PermTeamRead, domain.PermEnvironmentRead,
		domain.PermRoleBind, domain.PermRoleRead, domain.PermUserRead, domain.PermEntitlementsRead,
	}
	if got := slices.Clone(r.Permissions); !slices.Equal(sorted(got), sorted(want)) {
		t.Fatalf("permissions %v, want %v", got, want)
	}
	if r.ServiceOnly || r.HumanOnly() {
		t.Fatalf("Scope Admin: service only %v, human only %v", r.ServiceOnly, r.HumanOnly())
	}
	if _, err := domain.CheckBindable(domain.RoleScopeAdmin, domain.KindUser, domain.ScopeOrg); !errors.Is(err, domain.ErrScopeNotAllowed) {
		t.Fatalf("at org scope: %v", err)
	}
	for _, s := range []domain.ScopeType{domain.ScopeBusinessUnit, domain.ScopeTeam, domain.ScopeEnvironment} {
		if _, err := domain.CheckBindable(domain.RoleScopeAdmin, domain.KindUser, s); err != nil {
			t.Errorf("at %s: %v", s, err)
		}
	}
}

func sorted(ps []domain.Permission) []domain.Permission {
	slices.Sort(ps)
	return ps
}

// ceilingWorld is an org with two business units, a team in the first and
// an environment in that team, plus a team in the second unit.
type ceilingWorld struct {
	org                            ids.OrgID
	bu, bu2                        domain.Scope
	team, team2                    domain.Scope
	env                            domain.Scope
	orgP, buP, teamP, envP, team2P domain.Path
}

func newCeilingWorld() ceilingWorld {
	w := ceilingWorld{org: ids.New[ids.Org]()}
	w.bu = domain.Scope{Type: domain.ScopeBusinessUnit, ID: ids.NewV7()}
	w.bu2 = domain.Scope{Type: domain.ScopeBusinessUnit, ID: ids.NewV7()}
	w.team = domain.Scope{Type: domain.ScopeTeam, ID: ids.NewV7()}
	w.team2 = domain.Scope{Type: domain.ScopeTeam, ID: ids.NewV7()}
	w.env = domain.Scope{Type: domain.ScopeEnvironment, ID: ids.NewV7()}
	w.orgP = domain.OrgPath(w.org)
	w.buP = w.orgP.Child(w.bu.Type, w.bu.ID)
	w.teamP = w.buP.Child(w.team.Type, w.team.ID)
	w.envP = w.teamP.Child(w.env.Type, w.env.ID)
	w.team2P = w.orgP.Child(w.bu2.Type, w.bu2.ID).Child(w.team2.Type, w.team2.ID)
	return w
}

func (w ceilingWorld) person(bs ...domain.Binding) domain.Subject {
	return domain.Subject{Org: w.org, Principal: domain.PrincipalRef{Kind: domain.KindUser, ID: ids.NewV7()}, Bindings: bs}
}

// TestHR472_ScopedAdminBindsOnlyRolesItHoldsAtOrAboveTheTarget: a Scope
// Admin at a team that is also a Developer there binds Developer at the
// team and its environment, and re-delegates Scope Admin; it is refused a
// role it doesn't hold, a sibling team, its business unit, and a role it
// holds only at a sibling scope.
//
// Covers: F584
func TestHR472_ScopedAdminBindsOnlyRolesItHoldsAtOrAboveTheTarget(t *testing.T) {
	w := newCeilingWorld()
	s := w.person(
		domain.Binding{Role: domain.RoleScopeAdmin, Scope: w.team},
		domain.Binding{Role: domain.RoleDeveloper, Scope: w.team},
		domain.Binding{Role: domain.RoleApprover, Scope: w.team2},
	)
	for _, ok := range []struct {
		role domain.RoleName
		at   domain.Path
	}{
		{domain.RoleDeveloper, w.teamP},
		{domain.RoleDeveloper, w.envP},
		{domain.RoleScopeAdmin, w.envP},
		{domain.RoleScopeAdmin, w.teamP},
	} {
		if err := s.CheckBindCeiling(ok.role, ok.at); err != nil {
			t.Errorf("%s at %v refused: %v", ok.role, ok.at[len(ok.at)-1].Type, err)
		}
	}
	for _, bad := range []struct {
		role domain.RoleName
		at   domain.Path
		want error
	}{
		{domain.RoleAgentOwner, w.teamP, domain.ErrBindingCeiling}, // not held
		{domain.RoleApprover, w.envP, domain.ErrBindingCeiling},    // held only beside the target
		{domain.RoleDeveloper, w.buP, nil},                         // above its scope: no role.bind there
		{domain.RoleDeveloper, w.team2P, nil},                      // a sibling team
	} {
		err := s.CheckBindCeiling(bad.role, bad.at)
		if err == nil || (bad.want != nil && !errors.Is(err, bad.want)) {
			t.Errorf("%s at %v: got %v", bad.role, bad.at[len(bad.at)-1], err)
		}
	}
}

// TestHR473_OrgScopeRolesNeedOrgLevelRoleBind: an org-scope binding needs
// org-level role.bind, even for a role the Scope Admin holds at the org;
// an Org Admin binds any role anywhere.
//
// Covers: F584
func TestHR473_OrgScopeRolesNeedOrgLevelRoleBind(t *testing.T) {
	w := newCeilingWorld()
	s := w.person(
		domain.Binding{Role: domain.RoleScopeAdmin, Scope: w.bu},
		domain.Binding{Role: domain.RoleViewer, Scope: domain.Scope{Type: domain.ScopeOrg, ID: w.org.UUID()}},
	)
	if err := s.CheckBindCeiling(domain.RoleViewer, w.orgP); err == nil {
		t.Fatal("a Scope Admin bound a role at the org")
	}
	if err := s.CheckBindCeiling(domain.RoleViewer, w.teamP); err != nil {
		t.Fatalf("Viewer held at the org, bound in its unit: %v", err)
	}
	admin := w.person(domain.Binding{Role: domain.RoleOrgAdmin, Scope: domain.Scope{Type: domain.ScopeOrg, ID: w.org.UUID()}})
	for _, p := range []domain.Path{w.orgP, w.buP, w.envP, w.team2P} {
		if err := admin.CheckBindCeiling(domain.RoleSecurityAdmin, p); err != nil {
			t.Errorf("Org Admin refused at %v: %v", p[len(p)-1].Type, err)
		}
	}
}

// TestHR474_UnbindingFollowsTheSameCeiling: unbinding uses the same check
// with the binding's role and scope, so a Scope Admin cannot remove an Org
// Admin's or a sibling team's binding, nor one of a role it doesn't hold.
//
// Covers: F584
func TestHR474_UnbindingFollowsTheSameCeiling(t *testing.T) {
	w := newCeilingWorld()
	s := w.person(domain.Binding{Role: domain.RoleScopeAdmin, Scope: w.team}, domain.Binding{Role: domain.RoleDeveloper, Scope: w.team})
	if err := s.CheckBindCeiling(domain.RoleOrgAdmin, w.orgP); err == nil {
		t.Error("unbinding an Org Admin")
	}
	if err := s.CheckBindCeiling(domain.RoleDeveloper, w.team2P); err == nil {
		t.Error("unbinding at a sibling team")
	}
	if err := s.CheckBindCeiling(domain.RoleResponder, w.envP); !errors.Is(err, domain.ErrBindingCeiling) {
		t.Errorf("unbinding a role it doesn't hold: %v", err)
	}
	if err := s.CheckBindCeiling(domain.RoleDeveloper, w.envP); err != nil {
		t.Errorf("unbinding Developer in its environment: %v", err)
	}
}

// TestT206_ScopedAdminEscalation: escalation paths a Scope Admin might try.
// Without role.bind on the target nothing binds even for a held role; a
// break-glass binding is not "held" for delegation; a binding from another
// org grants nothing; an API key without role.bind in its scopes binds
// nothing.
//
// Covers: F584
func TestT206_ScopedAdminEscalation(t *testing.T) {
	w := newCeilingWorld()
	dev := w.person(domain.Binding{Role: domain.RoleDeveloper, Scope: w.team})
	if err := dev.CheckBindCeiling(domain.RoleDeveloper, w.envP); err == nil {
		t.Error("a Developer without role.bind delegated its role")
	}
	bg := w.person(
		domain.Binding{Role: domain.RoleScopeAdmin, Scope: w.team},
		domain.Binding{Role: domain.RoleResponder, Scope: w.team, BreakGlass: ids.NewV7()},
	)
	if err := bg.CheckBindCeiling(domain.RoleResponder, w.envP); !errors.Is(err, domain.ErrBindingCeiling) {
		t.Errorf("a break-glass binding was delegated: %v", err)
	}
	other := newCeilingWorld()
	if err := w.person(domain.Binding{Role: domain.RoleScopeAdmin, Scope: w.team}).CheckBindCeiling(domain.RoleScopeAdmin, other.envP); err == nil {
		t.Error("bound in another org")
	}
	key := w.person(domain.Binding{Role: domain.RoleScopeAdmin, Scope: w.team})
	key.Scopes = []domain.Permission{domain.PermRoleRead}
	if err := key.CheckBindCeiling(domain.RoleScopeAdmin, w.envP); err == nil {
		t.Error("an API key without role.bind bound a role")
	}
}

// TestM18_PermissionsAndRoles: the M18 permissions of G0 M18 D161 and the
// roles that hold them, exactly. identity_provider.manage is not in the
// human-only catalog, because Org Admin stays bindable to service accounts;
// the identity provider service refuses any caller but a person.
//
// Covers: PN-012.7
func TestM18_PermissionsAndRoles(t *testing.T) {
	want := map[domain.Permission][]domain.RoleName{
		domain.PermIdentityProviderRead:   {domain.RoleAuditor, domain.RoleOrgAdmin, domain.RoleSecurityAdmin},
		domain.PermIdentityProviderManage: {domain.RoleOrgAdmin},
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
	if _, err := domain.CheckBindable(domain.RoleOrgAdmin, domain.KindServiceAccount, domain.ScopeOrg); err != nil {
		t.Errorf("Org Admin is no longer bindable to service accounts: %v", err)
	}
}

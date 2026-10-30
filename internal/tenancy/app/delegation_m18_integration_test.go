// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// delegationWorld is an Enterprise org with two business units, a team in
// each and an environment in the first team, plus a user to bind.
type delegationWorld struct {
	f                *fixture
	a                *app.Access
	org              ids.OrgID
	bu, bu2          td.Scope
	team, team2, env td.Scope
	bob              td.UserID
}

func newDelegationWorld(t *testing.T) delegationWorld {
	t.Helper()
	f := newFixture(t)
	f.ents.edition = billing.Enterprise
	w := delegationWorld{f: f, a: app.NewAccess(f.pool, nil).WithEntitlements(f.ents), org: f.org(t, "acme")}
	ctx := adminOf(w.org)
	bu := must(f.h.CreateBusinessUnit(ctx, app.NewEntity{Slug: "payments", Name: "Payments"}))
	bu2 := must(f.h.CreateBusinessUnit(ctx, app.NewEntity{Slug: "lending", Name: "Lending"}))
	tm := must(f.h.CreateTeam(ctx, bu.ID, app.NewEntity{Slug: "refunds", Name: "Refunds"}))
	tm2 := must(f.h.CreateTeam(ctx, bu2.ID, app.NewEntity{Slug: "loans", Name: "Loans"}))
	env := must(f.h.CreateEnvironment(ctx, tm.ID, td.Production, app.NewEntity{Slug: "prod", Name: "Production"}))
	w.bu = td.Scope{Type: td.ScopeBusinessUnit, ID: bu.ID.UUID()}
	w.bu2 = td.Scope{Type: td.ScopeBusinessUnit, ID: bu2.ID.UUID()}
	w.team = td.Scope{Type: td.ScopeTeam, ID: tm.ID.UUID()}
	w.team2 = td.Scope{Type: td.ScopeTeam, ID: tm2.ID.UUID()}
	w.env = td.Scope{Type: td.ScopeEnvironment, ID: env.ID.UUID()}
	w.bob = f.user(t, w.org, "bob@example.test")
	return w
}

// TestHR472_ScopeAdminBindsOnlyRolesItHoldsInsideItsScope: a Scope Admin
// at a team who is also a Developer there binds Developer at the team and
// its environment, and Scope Admin below; it is refused at its business
// unit, at a sibling team, and for a role it doesn't hold.
//
// Covers: F584
func TestHR472_ScopeAdminBindsOnlyRolesItHoldsInsideItsScope(t *testing.T) {
	w := newDelegationWorld(t)
	ctx := as(w.org, td.Binding{Role: td.RoleScopeAdmin, Scope: w.team}, td.Binding{Role: td.RoleDeveloper, Scope: w.team})
	for _, ok := range []struct {
		role  td.RoleName
		scope td.Scope
	}{{td.RoleDeveloper, w.team}, {td.RoleDeveloper, w.env}, {td.RoleScopeAdmin, w.env}} {
		if _, _, err := w.a.CreateRoleBinding(ctx, ok.role, userRef(w.bob), ok.scope); err != nil {
			t.Errorf("%s at %s: %v", ok.role, ok.scope.Type, err)
		}
	}
	for name, bad := range map[string]struct {
		role  td.RoleName
		scope td.Scope
	}{
		"its business unit": {td.RoleDeveloper, w.bu},
		"a sibling team":    {td.RoleDeveloper, w.team2},
		"a role not held":   {td.RoleAgentOwner, w.team},
	} {
		_, _, err := w.a.CreateRoleBinding(ctx, bad.role, userRef(w.bob), bad.scope)
		if pcerr.CodeOf(err) != pcerr.PermissionDenied {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := w.f.auditCount(t, w.org, "access.role_bound"); n != 3 {
		t.Errorf("role_bound audited %d times, want 3", n)
	}
}

// TestHR473_ScopeAdminCannotBindOrgScopeRoles: org-scope bindings need
// org-level role.bind; the Org Admin binds them and binds Scope Admin.
func TestHR473_ScopeAdminCannotBindOrgScopeRoles(t *testing.T) {
	w := newDelegationWorld(t)
	ctx := as(w.org, td.Binding{Role: td.RoleScopeAdmin, Scope: w.bu}, orgRole(w.org, td.RoleViewer))
	for _, r := range []td.RoleName{td.RoleViewer, td.RoleOrgAdmin, td.RoleAuditor} {
		_, _, err := w.a.CreateRoleBinding(ctx, r, userRef(w.bob), orgScope(w.org))
		if pcerr.CodeOf(err) != pcerr.PermissionDenied {
			t.Errorf("Scope Admin bound %s at the org: %v", r, err)
		}
	}
	if _, _, err := w.a.CreateRoleBinding(adminOf(w.org), td.RoleScopeAdmin, userRef(w.bob), w.bu); err != nil {
		t.Fatalf("Org Admin binds Scope Admin: %v", err)
	}
	if _, _, err := w.a.CreateRoleBinding(adminOf(w.org), td.RoleScopeAdmin, userRef(w.bob), orgScope(w.org)); pcerr.CodeOf(err) != pcerr.InvalidArgument {
		t.Errorf("Scope Admin at the org: %v", err)
	}
}

// TestHR474_ScopeAdminUnbindsOnlyInsideItsCeiling: a Scope Admin removes
// a binding it could make, but not an org-scope binding, one at a sibling
// team or one of a role it doesn't hold.
func TestHR474_ScopeAdminUnbindsOnlyInsideItsCeiling(t *testing.T) {
	w := newDelegationWorld(t)
	admin := adminOf(w.org)
	inEnv := must2(w.a.CreateRoleBinding(admin, td.RoleDeveloper, userRef(w.bob), w.env))
	sibling := must2(w.a.CreateRoleBinding(admin, td.RoleDeveloper, userRef(w.bob), w.team2))
	notHeld := must2(w.a.CreateRoleBinding(admin, td.RoleResponder, userRef(w.bob), w.env))
	atOrg := must2(w.a.CreateRoleBinding(admin, td.RoleViewer, userRef(w.bob), orgScope(w.org)))
	ctx := as(w.org, td.Binding{Role: td.RoleScopeAdmin, Scope: w.team}, td.Binding{Role: td.RoleDeveloper, Scope: w.team},
		orgRole(w.org, td.RoleViewer))
	for name, b := range map[string]app.RoleBinding{"sibling team": sibling, "role not held": notHeld, "org scope": atOrg} {
		if err := w.a.DeleteRoleBinding(ctx, b.ID); pcerr.CodeOf(err) != pcerr.PermissionDenied {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := w.a.DeleteRoleBinding(ctx, inEnv.ID); err != nil {
		t.Fatalf("unbinding inside the ceiling: %v", err)
	}
}

// TestT206_ScopeAdminEscalation: re-delegated Scope Admins stay below the
// scope they were given, and binding Scope Admin needs Enterprise.
func TestT206_ScopeAdminEscalation(t *testing.T) {
	w := newDelegationWorld(t)
	// A Scope Admin re-delegated at the environment cannot reach back up
	// to the team.
	ctx := as(w.org, td.Binding{Role: td.RoleScopeAdmin, Scope: w.env}, td.Binding{Role: td.RoleDeveloper, Scope: w.env})
	if _, _, err := w.a.CreateRoleBinding(ctx, td.RoleScopeAdmin, userRef(w.bob), w.team); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Errorf("re-delegated Scope Admin bound upwards: %v", err)
	}
	if _, _, err := w.a.CreateRoleBinding(ctx, td.RoleDeveloper, userRef(w.bob), w.team); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Errorf("bound Developer above its scope: %v", err)
	}
	for _, ed := range []billing.Edition{billing.Community, billing.Team, billing.Business} {
		w.f.ents.edition = ed
		_, _, err := w.a.CreateRoleBinding(adminOf(w.org), td.RoleScopeAdmin, userRef(w.bob), w.bu2)
		wantCode(t, string(ed), err, pcerr.FailedPrecondition, "EDITION_REQUIRED")
	}
}

// TestHR474_UnbindingWorksAfterADowngrade: a downgrade never locks anyone
// out (D161). Scope Admin bindings made under Enterprise stay; their holder
// still binds and unbinds inside its ceiling, and the Org Admin removes the
// Scope Admin binding itself, all without the edition.
//
// Covers: F584
func TestHR474_UnbindingWorksAfterADowngrade(t *testing.T) {
	w := newDelegationWorld(t)
	admin := adminOf(w.org)
	sa := must2(w.a.CreateRoleBinding(admin, td.RoleScopeAdmin, userRef(w.bob), w.team))
	dev := must2(w.a.CreateRoleBinding(admin, td.RoleDeveloper, userRef(w.bob), w.env))
	w.f.ents.edition = billing.Community
	ctx := as(w.org, td.Binding{Role: td.RoleScopeAdmin, Scope: w.team}, td.Binding{Role: td.RoleDeveloper, Scope: w.team})
	if err := w.a.DeleteRoleBinding(ctx, dev.ID); err != nil {
		t.Fatalf("Scope Admin unbinding after the downgrade: %v", err)
	}
	if err := w.a.DeleteRoleBinding(admin, sa.ID); err != nil {
		t.Fatalf("Org Admin removing the Scope Admin binding after the downgrade: %v", err)
	}
}

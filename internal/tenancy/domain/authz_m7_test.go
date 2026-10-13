// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// holders returns the default roles that hold p, sorted.
func holders(p domain.Permission) []domain.RoleName {
	var out []domain.RoleName
	for _, r := range domain.Roles() {
		if r.Has(p) {
			out = append(out, r.Name)
		}
	}
	slices.Sort(out)
	return out
}

// m7HumanOnly are the permissions G0 M7 adds for people only.
var m7HumanOnly = []domain.Permission{
	domain.PermTransactionReconcile, domain.PermEvidenceExport, domain.PermEvidenceRetentionManage,
	domain.PermEvidenceCaptureManage,
}

// TestM7_EvidencePermissionsAndRoles: the permission set and role changes
// of G0 M7 (Contracts → Permissions), exactly.
func TestM7_EvidencePermissionsAndRoles(t *testing.T) {
	want := map[domain.Permission][]domain.RoleName{
		domain.PermEvidenceRead: {
			domain.RoleAgentOwner, domain.RoleAuditor, domain.RoleDeveloper, domain.RoleOrgAdmin, domain.RoleReconciler,
			domain.RoleRecordsManager, domain.RoleResponder, domain.RoleSecurityAdmin,
		},
		domain.PermEvidenceExport:          {domain.RoleAuditor, domain.RoleSecurityAdmin},
		domain.PermTransactionReconcile:    {domain.RoleReconciler, domain.RoleSecurityAdmin},
		domain.PermEvidenceRetentionManage: {domain.RoleRecordsManager},
		domain.PermEvidenceCaptureManage:   {domain.RoleRecordsManager},
		domain.PermEvidenceReadRestricted:  {domain.RoleAuditor},
	}
	for p, roles := range want {
		if !p.Known() {
			t.Errorf("%s is not in the catalog", p)
		}
		slices.Sort(roles)
		if got := holders(p); !slices.Equal(got, roles) {
			t.Errorf("%s is held by %v, want %v", p, got, roles)
		}
	}
	rec, ok := domain.LookupRole(domain.RoleReconciler)
	if !ok || !slices.Equal(rec.Scopes, []domain.ScopeType{
		domain.ScopeOrg, domain.ScopeBusinessUnit, domain.ScopeTeam, domain.ScopeEnvironment,
	}) {
		t.Errorf("Reconciler scopes %v, want any scope", rec.Scopes)
	}
	// waitlist.read lets a Reconciler see and take the RECONCILIATION
	// entries routed to them (G0 M7 slice A11; M5 part 2: waitlist.read
	// reaches everyone entries are routed to).
	for _, p := range []domain.Permission{
		domain.PermTransactionReconcile, domain.PermEvidenceRead, domain.PermRunRead, domain.PermAgentRead, domain.PermWaitlistRead,
	} {
		if !rec.Has(p) {
			t.Errorf("Reconciler lacks %s", p)
		}
	}
	rm, ok := domain.LookupRole(domain.RoleRecordsManager)
	if !ok || !slices.Equal(rm.Scopes, []domain.ScopeType{domain.ScopeOrg}) {
		t.Errorf("Records Manager scopes %v, want org only", rm.Scopes)
	}
}

// TestHR192_OnlyPeopleResolveUnknownOutcomes: resolving, releasing and
// linking reconciliations (transaction.reconcile), exporting packs,
// retention and capture are human only. Neither new role can be bound to a
// service account, no API key can carry them, and a service account bound
// to every role still holds none of them.
func TestHR192_OnlyPeopleResolveUnknownOutcomes(t *testing.T) {
	for _, p := range m7HumanOnly {
		if !p.HumanOnly() || p.APIKeyScopable() || p.Gateway() {
			t.Errorf("%s must be human only", p)
		}
		if err := domain.CheckAPIKeyScopes([]domain.Permission{p}); !errors.Is(err, domain.ErrHumanOnlyScope) {
			t.Errorf("API key scope %s: %v", p, err)
		}
	}
	if p := domain.PermEvidenceRead; p.HumanOnly() || !p.APIKeyScopable() {
		t.Error("evidence.read must be open to service accounts and API keys")
	}
	for _, r := range []domain.RoleName{domain.RoleReconciler, domain.RoleRecordsManager} {
		if _, err := domain.CheckBindable(r, domain.KindServiceAccount, domain.ScopeOrg); !errors.Is(err, domain.ErrHumanOnlyRole) {
			t.Errorf("%s bindable to a service account: %v", r, err)
		}
		if _, err := domain.CheckBindable(r, domain.KindUser, domain.ScopeOrg); err != nil {
			t.Errorf("%s not bindable to a user: %v", r, err)
		}
	}
	if _, err := domain.CheckBindable(domain.RoleRecordsManager, domain.KindUser, domain.ScopeTeam); !errors.Is(err, domain.ErrScopeNotAllowed) {
		t.Errorf("Records Manager bindable at a team: %v", err)
	}
	tr := newTree()
	if _, err := domain.CheckBindable(domain.RoleReconciler, domain.KindUser, domain.ScopeTeam); err != nil {
		t.Errorf("Reconciler not bindable at a team: %v", err)
	}
	var bs []domain.Binding
	for _, r := range domain.Roles() {
		bs = append(bs, bind(r.Name, domain.ScopeOrg, tr.org.UUID()))
	}
	sa := serviceAccount(tr.org, bs...)
	for _, p := range m7HumanOnly {
		if sa.CanAnywhere(p) {
			t.Errorf("a service account bound to every role holds %s", p)
		}
	}
	if !sa.CanAnywhere(domain.PermEvidenceRead) {
		t.Error("a service account bound to Org Admin cannot read evidence")
	}
	teamReconciler := user(tr.org, bind(domain.RoleReconciler, domain.ScopeTeam, tr.team))
	if !teamReconciler.Can(domain.PermTransactionReconcile, domain.OrgPath(tr.org).Child(domain.ScopeTeam, tr.team)) ||
		teamReconciler.Can(domain.PermTransactionReconcile, domain.OrgPath(tr.org).Child(domain.ScopeTeam, tr.other)) {
		t.Error("a team's Reconciler must reconcile in that team only")
	}
}

// TestT043_OrgAdminReadsEvidenceOnly: Org Admin gets evidence.read but
// neither export, restricted evidence, retention, capture nor
// reconciliation (G0 M7 roles, F583).
func TestT043_OrgAdminReadsEvidenceOnly(t *testing.T) {
	tr := newTree()
	admin := user(tr.org, bind(domain.RoleOrgAdmin, domain.ScopeOrg, tr.org.UUID()))
	if !admin.CanAnywhere(domain.PermEvidenceRead) {
		t.Error("Org Admin cannot read evidence")
	}
	for _, p := range append(slices.Clone(m7HumanOnly), domain.PermEvidenceReadRestricted) {
		if admin.CanAnywhere(p) {
			t.Errorf("Org Admin holds %s", p)
		}
	}
}

// TestHR199_WhoConfiguresCaptureCannotReadIt: the Records Manager sets
// capture and retention and never reads captures; the Auditor reads them
// and configures neither.
func TestHR199_WhoConfiguresCaptureCannotReadIt(t *testing.T) {
	for _, r := range domain.Roles() {
		if r.Has(domain.PermEvidenceCaptureManage) && r.Has(domain.PermEvidenceReadRestricted) {
			t.Errorf("role %s both configures and reads captures", r.Name)
		}
	}
	if !domain.PermEvidenceReadRestricted.HumanOnly() {
		t.Error("evidence.read_restricted must stay human only")
	}
}

// TestHR190_GatewayVerifyIsAGatewayPermission: only gateways lease and
// report verifications; no role grants it.
func TestHR190_GatewayVerifyIsAGatewayPermission(t *testing.T) {
	p := domain.PermGatewayVerify
	if !p.Gateway() || p.Known() || !p.Declarable() || p.APIKeyScopable() {
		t.Errorf("%s: gateway=%v known=%v declarable=%v", p, p.Gateway(), p.Known(), p.Declarable())
	}
	if got := holders(p); len(got) != 0 {
		t.Errorf("%s is held by %v", p, got)
	}
}

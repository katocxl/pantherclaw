// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"regexp"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type tree struct {
	org         ids.OrgID
	bu, otherBU ids.UUID
	team, other ids.UUID
	env         ids.UUID
}

func newTree() tree {
	return tree{
		org: ids.New[ids.Org](), bu: ids.NewV7(), otherBU: ids.NewV7(),
		team: ids.NewV7(), other: ids.NewV7(), env: ids.NewV7(),
	}
}

// envPath: org → bu → team → env.
func (t tree) envPath() domain.Path {
	return domain.OrgPath(t.org).Child(domain.ScopeBusinessUnit, t.bu).Child(domain.ScopeTeam, t.team).
		Child(domain.ScopeEnvironment, t.env)
}

func user(org ids.OrgID, bs ...domain.Binding) domain.Subject {
	return domain.Subject{Org: org, Principal: domain.PrincipalRef{Kind: domain.KindUser, ID: ids.NewV7()}, Bindings: bs}
}

func serviceAccount(org ids.OrgID, bs ...domain.Binding) domain.Subject {
	return domain.Subject{Org: org, Principal: domain.PrincipalRef{Kind: domain.KindServiceAccount, ID: ids.NewV7()}, Bindings: bs}
}

func bind(r domain.RoleName, t domain.ScopeType, id ids.UUID) domain.Binding {
	return domain.Binding{Role: r, Scope: domain.Scope{Type: t, ID: id}}
}

func TestScopeInheritanceIsDownwardsOnly(t *testing.T) {
	tr := newTree()
	teamOwner := user(tr.org, bind(domain.RoleAgentOwner, domain.ScopeTeam, tr.team))
	if !teamOwner.Can(domain.PermAgentManage, tr.envPath()) {
		t.Error("team binding does not apply to an environment of the team")
	}
	teamPath := domain.OrgPath(tr.org).Child(domain.ScopeBusinessUnit, tr.bu).Child(domain.ScopeTeam, tr.team)
	if !teamOwner.Can(domain.PermAgentManage, teamPath) {
		t.Error("team binding does not apply to the team")
	}
	if teamOwner.Can(domain.PermAgentManage, domain.OrgPath(tr.org).Child(domain.ScopeBusinessUnit, tr.bu)) {
		t.Error("team binding applies upwards to its business unit")
	}
	sibling := domain.OrgPath(tr.org).Child(domain.ScopeBusinessUnit, tr.bu).Child(domain.ScopeTeam, tr.other)
	if teamOwner.Can(domain.PermAgentManage, sibling) {
		t.Error("team binding applies to a sibling team")
	}
	buOwner := user(tr.org, bind(domain.RoleAgentOwner, domain.ScopeBusinessUnit, tr.bu))
	if !buOwner.Can(domain.PermAgentManage, tr.envPath()) {
		t.Error("business-unit binding does not reach its team's environment")
	}
	if buOwner.Can(domain.PermAgentManage, domain.OrgPath(tr.org).Child(domain.ScopeBusinessUnit, tr.otherBU)) {
		t.Error("business-unit binding applies to another business unit")
	}
	admin := user(tr.org, bind(domain.RoleOrgAdmin, domain.ScopeOrg, tr.org.UUID()))
	if !admin.Can(domain.PermTeamManage, sibling) || !admin.Can(domain.PermEnvironmentManage, tr.envPath()) {
		t.Error("org binding does not apply everywhere in the org")
	}
}

func TestSubjectCannotActInAnotherOrg(t *testing.T) {
	tr := newTree()
	admin := user(tr.org, bind(domain.RoleOrgAdmin, domain.ScopeOrg, tr.org.UUID()))
	other := ids.New[ids.Org]()
	if admin.Can(domain.PermTeamManage, domain.OrgPath(other)) {
		t.Fatal("subject authorized on another org's path")
	}
	// A forged binding naming the other org's id still does not apply.
	forged := user(tr.org, bind(domain.RoleOrgAdmin, domain.ScopeOrg, other.UUID()))
	if forged.Can(domain.PermTeamManage, domain.OrgPath(other)) {
		t.Fatal("binding on another org's scope authorized the subject there")
	}
	if admin.Can(domain.PermTeamManage, nil) {
		t.Fatal("empty path authorized")
	}
}

func TestUnknownRolesAndPermissionsGrantNothing(t *testing.T) {
	tr := newTree()
	s := user(tr.org, bind("superuser", domain.ScopeOrg, tr.org.UUID()))
	if s.CanAnywhere(domain.PermOrgRead) || len(s.Permissions()) != 0 {
		t.Fatal("unknown role granted permissions")
	}
	admin := user(tr.org, bind(domain.RoleOrgAdmin, domain.ScopeOrg, tr.org.UUID()))
	for _, p := range []domain.Permission{"org.*", "", domain.PermPublic, domain.PermAuthenticated, domain.PermGatewayAuthorize} {
		if admin.Can(p, domain.OrgPath(tr.org)) || admin.CanAnywhere(p) {
			t.Errorf("admin holds %q", p)
		}
	}
}

func TestAPIKeyScopesIntersectBindings(t *testing.T) {
	tr := newTree()
	sa := serviceAccount(tr.org, bind(domain.RoleOrgAdmin, domain.ScopeOrg, tr.org.UUID()))
	sa.Scopes = []domain.Permission{domain.PermTeamRead}
	if !sa.Can(domain.PermTeamRead, domain.OrgPath(tr.org)) {
		t.Error("scoped key lost a scoped permission its account holds")
	}
	if sa.Can(domain.PermTeamManage, domain.OrgPath(tr.org)) {
		t.Error("scoped key used a permission outside its scopes")
	}
	viewer := serviceAccount(tr.org, bind(domain.RoleViewer, domain.ScopeOrg, tr.org.UUID()))
	viewer.Scopes = []domain.Permission{domain.PermTeamManage}
	if viewer.Can(domain.PermTeamManage, domain.OrgPath(tr.org)) {
		t.Error("scopes granted a permission the account does not hold")
	}
	sa.Scopes = []domain.Permission{}
	if len(sa.Permissions()) != 0 {
		t.Error("empty scope list permits something")
	}
}

// TestT043_OrgAdminHoldsNoApprovalPublicationOrRestrictedEvidence: platform
// administration never implies business approval, policy publication or
// restricted evidence access (F583).
func TestT043_OrgAdminHoldsNoApprovalPublicationOrRestrictedEvidence(t *testing.T) {
	tr := newTree()
	for _, r := range []domain.RoleName{domain.RoleOrgAdmin, domain.RoleSecurityAdmin} {
		admin := user(tr.org, bind(r, domain.ScopeOrg, tr.org.UUID()))
		for _, p := range []domain.Permission{domain.PermApprovalRespond, domain.PermPolicyPublish, domain.PermEvidenceReadRestricted} {
			if admin.CanAnywhere(p) {
				t.Errorf("%s holds %s", r, p)
			}
		}
	}
	// Approve and publish come from their own roles only: approval from the
	// Approver and the release-control roles a requirement can name (G0 M8,
	// HR-207).
	approvers := []domain.RoleName{domain.RoleApprover, domain.RoleCodeReviewer, domain.RoleReleaseApprover}
	for _, r := range domain.Roles() {
		if r.Has(domain.PermApprovalRespond) != slices.Contains(approvers, r.Name) {
			t.Errorf("role %s: approval.respond = %v", r.Name, r.Has(domain.PermApprovalRespond))
		}
		if r.Has(domain.PermPolicyPublish) && r.Name != domain.RolePolicyPublisher {
			t.Errorf("role %s can publish policies", r.Name)
		}
		if r.Has(domain.PermPolicyPublish) && r.Has(domain.PermPolicyAuthor) {
			t.Errorf("role %s both authors and publishes policies (F582)", r.Name)
		}
	}
}

// TestT043_NonHumansNeverHoldHumanOnlyPermissions: service accounts and API
// keys can never approve, publish or read restricted evidence, even when a
// binding to a human-only role exists (defense in depth behind
// CheckBindable).
func TestT043_NonHumansNeverHoldHumanOnlyPermissions(t *testing.T) {
	tr := newTree()
	var bs []domain.Binding
	for _, r := range domain.Roles() {
		bs = append(bs, bind(r.Name, domain.ScopeOrg, tr.org.UUID()))
	}
	sa := serviceAccount(tr.org, bs...)
	key := sa
	key.Scopes = domain.Catalog()
	for _, s := range []domain.Subject{sa, key} {
		for _, p := range domain.Catalog() {
			if p.HumanOnly() && (s.CanAnywhere(p) || s.Can(p, domain.OrgPath(tr.org))) {
				t.Errorf("service account (scopes=%v) holds human-only %s", s.Scopes != nil, p)
			}
		}
	}
	human := user(tr.org, bs...)
	if !human.CanAnywhere(domain.PermApprovalRespond) {
		t.Fatal("approver binding does not work for a human")
	}
	for _, r := range domain.Roles() {
		// At a scope the role may be bound at, so only being human only
		// can refuse it.
		_, err := domain.CheckBindable(r.Name, domain.KindServiceAccount, r.Scopes[0])
		if r.HumanOnly() != errors.Is(err, domain.ErrHumanOnlyRole) {
			t.Errorf("CheckBindable(%s, service account) = %v", r.Name, err)
		}
	}
	if err := domain.CheckAPIKeyScopes([]domain.Permission{domain.PermApprovalRespond}); !errors.Is(err, domain.ErrHumanOnlyScope) {
		t.Errorf("API key scope approval.respond: %v", err)
	}
}

func TestRoleCatalogIsWellFormed(t *testing.T) {
	name := regexp.MustCompile(`^[a-z][a-z_]{0,62}$`) // matches the role_bindings CHECK
	seen := map[domain.RoleName]bool{}
	for _, r := range domain.Roles() {
		if !name.MatchString(string(r.Name)) || seen[r.Name] {
			t.Errorf("role name %q invalid or duplicated", r.Name)
		}
		seen[r.Name] = true
		if r.Title == "" || r.Description == "" || len(r.Scopes) == 0 || len(r.Permissions) == 0 {
			t.Errorf("role %s is incomplete", r.Name)
		}
		for _, p := range r.Permissions {
			if !p.Known() || p.Gateway() {
				t.Errorf("role %s contains %q", r.Name, p)
			}
		}
		if !r.Has(domain.PermOrgRead) {
			t.Errorf("role %s cannot read its org", r.Name)
		}
	}
	for _, n := range []domain.RoleName{
		domain.RoleOrgAdmin, domain.RoleSecurityAdmin, domain.RoleAgentOwner,
		domain.RolePolicyAuthor, domain.RolePolicyPublisher, domain.RoleApprover, domain.RoleResponder,
		domain.RoleAuditor, domain.RoleDeveloper, domain.RoleViewer, domain.RoleRunLauncher,
		domain.RoleAgentAdmitter, domain.RoleIdentityPublisher, domain.RoleGrantIssuer, domain.RoleFactProvider,
	} {
		if !seen[n] {
			t.Errorf("default role %s missing (SB-2)", n)
		}
	}
	// Mutating the returned copies does not change the catalog.
	rs := domain.Roles()
	rs[0].Permissions[0] = domain.PermApprovalRespond
	if r, _ := domain.LookupRole(rs[0].Name); r.Has(domain.PermApprovalRespond) {
		t.Fatal("Roles() exposes the internal catalog")
	}
	cat := domain.Catalog()
	if len(cat) != len(slices.Compact(slices.Clone(cat))) {
		t.Fatal("catalog has duplicates")
	}
}

func TestCheckBindableScopes(t *testing.T) {
	if _, err := domain.CheckBindable(domain.RoleOrgAdmin, domain.KindUser, domain.ScopeTeam); !errors.Is(err, domain.ErrScopeNotAllowed) {
		t.Errorf("org_admin at team scope: %v", err)
	}
	if _, err := domain.CheckBindable(domain.RoleAgentOwner, domain.KindServiceAccount, domain.ScopeEnvironment); err != nil {
		t.Errorf("agent_owner at environment scope for a service account: %v", err)
	}
	if _, err := domain.CheckBindable("root", domain.KindUser, domain.ScopeOrg); !errors.Is(err, domain.ErrUnknownRole) {
		t.Errorf("unknown role: %v", err)
	}
	if _, err := domain.CheckBindable(domain.RoleViewer, domain.KindUser, "GALAXY"); !errors.Is(err, domain.ErrScopeNotAllowed) {
		t.Errorf("unknown scope type: %v", err)
	}
}

func TestSoDPrimitives(t *testing.T) {
	a := domain.PrincipalRef{Kind: domain.KindUser, ID: ids.NewV7()}
	b := domain.PrincipalRef{Kind: domain.KindUser, ID: ids.NewV7()}
	sameIDOtherKind := domain.PrincipalRef{Kind: domain.KindServiceAccount, ID: a.ID}
	if domain.Distinct(a, a) || !domain.Distinct(a, b) || !domain.Distinct(a, sameIDOtherKind) {
		t.Fatal("Distinct is wrong")
	}
	if !domain.SelfGrant(a, a) || domain.SelfGrant(a, b) {
		t.Fatal("SelfGrant is wrong")
	}
	for _, tc := range []struct {
		scopes []domain.Permission
		ok     bool
	}{
		{[]domain.Permission{domain.PermTeamRead, domain.PermTeamManage}, true},
		{nil, false},
		{[]domain.Permission{"team.*"}, false},
		{[]domain.Permission{domain.PermTeamRead, domain.PermTeamRead}, false},
		{[]domain.Permission{domain.PermGatewayAuthorize}, false},
	} {
		if err := domain.CheckAPIKeyScopes(tc.scopes); (err == nil) != tc.ok {
			t.Errorf("CheckAPIKeyScopes(%v) = %v", tc.scopes, err)
		}
	}
}

func TestPermissionsListsHeldPermissions(t *testing.T) {
	tr := newTree()
	v := user(tr.org, bind(domain.RoleViewer, domain.ScopeTeam, tr.team))
	got := v.Permissions()
	want := []domain.Permission{
		domain.PermOrgRead, domain.PermBusinessUnitRead, domain.PermTeamRead, domain.PermEnvironmentRead,
		domain.PermIncidentRead, domain.PermOperationsRead,
	} // Viewer sees incidents and the operations view (G0 M10 D4)
	if !slices.Equal(got, want) {
		t.Fatalf("Permissions() = %v, want %v", got, want)
	}
	if err := v.Require(domain.PermTeamManage, domain.OrgPath(tr.org)); err == nil {
		t.Fatal("Require allowed a missing permission")
	}
}

// TestHR146_OnlyTheRunLauncherRoleMayRepresentUsers: presenting a subject
// token to start a run for someone else (run.represent) is a deliberate
// grant of its own, never part of another default role.
func TestHR146_OnlyTheRunLauncherRoleMayRepresentUsers(t *testing.T) {
	for _, r := range domain.Roles() {
		if got := r.Has(domain.PermRunRepresent); got != (r.Name == domain.RoleRunLauncher) {
			t.Errorf("role %s: run.represent = %v", r.Name, got)
		}
	}
	if !domain.PermRunRepresent.APIKeyScopable() {
		t.Error("run.represent must be usable by service launchers")
	}
}

// TestHR094_AdmissionIsHumanOnly: confirming an instance's fingerprint is
// never available to a service account or API key, and no administrator or
// owner role contains it implicitly.
func TestHR094_AdmissionIsHumanOnly(t *testing.T) {
	if !domain.PermAgentAdmit.HumanOnly() || domain.PermAgentAdmit.APIKeyScopable() {
		t.Fatal("agent.admit must be human only")
	}
	for _, r := range domain.Roles() {
		if r.Has(domain.PermAgentAdmit) != (r.Name == domain.RoleAgentAdmitter) {
			t.Errorf("role %s: agent.admit = %v", r.Name, r.Has(domain.PermAgentAdmit))
		}
	}
	if _, err := domain.CheckBindable(domain.RoleAgentAdmitter, domain.KindServiceAccount, domain.ScopeTeam); !errors.Is(err, domain.ErrHumanOnlyRole) {
		t.Errorf("agent_admitter bound to a service account: %v", err)
	}
	// Service accounts keep being able to own and enroll agents.
	if _, err := domain.CheckBindable(domain.RoleAgentOwner, domain.KindServiceAccount, domain.ScopeTeam); err != nil {
		t.Errorf("agent_owner for a service account: %v", err)
	}
}

// TestHR141_IssuerActivationIsHumanOnlyAndSeparate: switching on a trusted
// issuer is a protected change (F582): human only, outside Org Admin, and no
// default role both proposes and activates.
func TestHR141_IssuerActivationIsHumanOnlyAndSeparate(t *testing.T) {
	if !domain.PermIssuerActivate.HumanOnly() || domain.PermIssuerActivate.APIKeyScopable() {
		t.Fatal("identity.issuer.activate must be human only")
	}
	for _, r := range domain.Roles() {
		if r.Has(domain.PermIssuerActivate) != (r.Name == domain.RoleIdentityPublisher) {
			t.Errorf("role %s: identity.issuer.activate = %v", r.Name, r.Has(domain.PermIssuerActivate))
		}
		if r.Has(domain.PermIssuerActivate) && r.Has(domain.PermIssuerManage) {
			t.Errorf("role %s both proposes and activates issuer entries", r.Name)
		}
	}
	tr := newTree()
	admin := user(tr.org, bind(domain.RoleOrgAdmin, domain.ScopeOrg, tr.org.UUID()))
	if admin.CanAnywhere(domain.PermIssuerActivate) || !admin.CanAnywhere(domain.PermIssuerManage) {
		t.Error("Org Admin must propose but not activate issuer entries")
	}
}

// TestWorkloadAndGatewayPermissionsAreNeverGrantable: only authenticated
// workloads and gateways exercise them; no role, binding or API key can.
func TestWorkloadAndGatewayPermissionsAreNeverGrantable(t *testing.T) {
	for _, p := range []domain.Permission{
		domain.PermWorkloadEnroll, domain.PermWorkloadToken, domain.PermWorkloadRun, domain.PermWorkloadDelegate,
		domain.PermGatewayObserve,
	} {
		if p.Known() || !p.Declarable() || p.APIKeyScopable() {
			t.Errorf("%s: known=%v declarable=%v scopable=%v", p, p.Known(), p.Declarable(), p.APIKeyScopable())
		}
	}
}

// TestHR161_GrantIssuanceAndGuardrailChangesAreHumanOnly: only people
// issue grants (decision 7) and change guardrails; platform and security
// administration imply neither, and the issuer cannot change the
// guardrails its grants must fit in.
func TestHR161_GrantIssuanceAndGuardrailChangesAreHumanOnly(t *testing.T) {
	for _, p := range []domain.Permission{domain.PermGrantIssue, domain.PermGuardrailsManage} {
		if !p.HumanOnly() || p.APIKeyScopable() {
			t.Errorf("%s must be human only", p)
		}
	}
	for _, r := range domain.Roles() {
		if r.Has(domain.PermGrantIssue) != (r.Name == domain.RoleGrantIssuer) {
			t.Errorf("role %s: grant.issue = %v", r.Name, r.Has(domain.PermGrantIssue))
		}
		if r.Has(domain.PermGuardrailsManage) != (r.Name == domain.RolePolicyPublisher) {
			t.Errorf("role %s: guardrails.manage = %v", r.Name, r.Has(domain.PermGuardrailsManage))
		}
		if r.Has(domain.PermGrantIssue) && r.Has(domain.PermGuardrailsManage) {
			t.Errorf("role %s both issues grants and changes guardrails", r.Name)
		}
	}
	tr := newTree()
	for _, r := range []domain.RoleName{domain.RoleOrgAdmin, domain.RoleSecurityAdmin} {
		admin := user(tr.org, bind(r, domain.ScopeOrg, tr.org.UUID()))
		if admin.CanAnywhere(domain.PermGrantIssue) || admin.CanAnywhere(domain.PermGuardrailsManage) {
			t.Errorf("%s can issue grants or change guardrails", r)
		}
	}
	sa := serviceAccount(tr.org, bind(domain.RoleGrantIssuer, domain.ScopeOrg, tr.org.UUID()))
	if sa.CanAnywhere(domain.PermGrantIssue) {
		t.Error("a service account bound to Grant Issuer can issue grants")
	}
	if _, err := domain.CheckBindable(domain.RoleGrantIssuer, domain.KindServiceAccount, domain.ScopeTeam); !errors.Is(err, domain.ErrHumanOnlyRole) {
		t.Errorf("Grant Issuer bindable to a service account: %v", err)
	}
}

// TestHR160_FactProvidersAreManagedByPeopleAndWrittenByTheirAccounts:
// registering a provider is human only; reporting facts is for service
// accounts (the provider's own, checked by the use case), and no role does
// both.
func TestHR160_FactProvidersAreManagedByPeopleAndWrittenByTheirAccounts(t *testing.T) {
	if !domain.PermFactProviderManage.HumanOnly() || domain.PermFactWrite.HumanOnly() {
		t.Fatal("fact.provider.manage must be human only and fact.write must not be")
	}
	for _, r := range domain.Roles() {
		if r.Has(domain.PermFactProviderManage) && r.Has(domain.PermFactWrite) {
			t.Errorf("role %s both registers providers and writes facts", r.Name)
		}
		if r.Has(domain.PermFactWrite) != (r.Name == domain.RoleFactProvider) {
			t.Errorf("role %s: fact.write = %v", r.Name, r.Has(domain.PermFactWrite))
		}
	}
	if _, err := domain.CheckBindable(domain.RoleFactProvider, domain.KindServiceAccount, domain.ScopeOrg); err != nil {
		t.Errorf("Fact Provider must be bindable to a service account: %v", err)
	}
}

// TestHR123_PackageImportAndActivationAreSeparate: importing a signed
// package changes nothing; activating it is a separate, human-only step
// that no role combines with importing.
func TestHR123_PackageImportAndActivationAreSeparate(t *testing.T) {
	if !domain.PermPackageActivate.HumanOnly() || domain.PermPackageActivate.APIKeyScopable() {
		t.Fatal("package.activate must be human only")
	}
	for _, r := range domain.Roles() {
		if r.Has(domain.PermPackageImport) && r.Has(domain.PermPackageActivate) {
			t.Errorf("role %s both imports and activates packages", r.Name)
		}
	}
}

// TestHR162_PackageKeysAreAnOrgAdminTask: only Org Admin registers the
// org's package-signing keys (decision answered 2026-10-09), and no role
// both registers keys and activates packages, so an org-signed package
// takes two roles to start deciding.
func TestHR162_PackageKeysAreAnOrgAdminTask(t *testing.T) {
	for _, r := range domain.Roles() {
		if r.Has(domain.PermPackageKeyManage) != (r.Name == domain.RoleOrgAdmin) {
			t.Errorf("role %s: package.key.manage = %v", r.Name, r.Has(domain.PermPackageKeyManage))
		}
		if r.Has(domain.PermPackageKeyManage) && r.Has(domain.PermPackageActivate) {
			t.Errorf("role %s both registers signing keys and activates packages", r.Name)
		}
	}
	if !domain.PermPackageKeyManage.Known() {
		t.Fatal("package.key.manage is not in the catalog")
	}
}

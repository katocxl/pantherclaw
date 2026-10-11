// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "slices"

// RoleName identifies a default role (SB-2, F581). Custom roles are a later,
// Enterprise feature.
type RoleName string

// Default roles.
const (
	RoleOrgAdmin          RoleName = "org_admin"
	RoleSecurityAdmin     RoleName = "security_admin"
	RoleAgentOwner        RoleName = "agent_owner"
	RolePolicyAuthor      RoleName = "policy_author"
	RolePolicyPublisher   RoleName = "policy_publisher"
	RoleApprover          RoleName = "approver"
	RoleResponder         RoleName = "responder"
	RoleAuditor           RoleName = "auditor"
	RoleDeveloper         RoleName = "developer"
	RoleViewer            RoleName = "viewer"
	RoleRunLauncher       RoleName = "run_launcher"
	RoleAgentAdmitter     RoleName = "agent_admitter"
	RoleIdentityPublisher RoleName = "identity_publisher"
	RoleGrantIssuer       RoleName = "grant_issuer"
	RoleFactProvider      RoleName = "fact_provider"
	RoleGatewayAdmin      RoleName = "gateway_admin"
	RoleEmergency         RoleName = "emergency_responder"
	RoleReconciler        RoleName = "reconciler"
	RoleRecordsManager    RoleName = "records_manager"
)

// Role is a named set of permissions and the scope types it may be bound at.
type Role struct {
	Name        RoleName
	Title       string
	Description string
	Permissions []Permission
	Scopes      []ScopeType
}

// Has reports whether the role contains p.
func (r Role) Has(p Permission) bool { return slices.Contains(r.Permissions, p) }

// HumanOnly reports whether the role contains a human-only permission; such
// a role can never be bound to a service account.
func (r Role) HumanOnly() bool { return slices.ContainsFunc(r.Permissions, Permission.HumanOnly) }

// BindableAt reports whether the role may be bound at scope type t.
func (r Role) BindableAt(t ScopeType) bool { return slices.Contains(r.Scopes, t) }

var (
	anyScope = []ScopeType{ScopeOrg, ScopeBusinessUnit, ScopeTeam, ScopeEnvironment}
	orgScope = []ScopeType{ScopeOrg}
	// basicReads lets a principal see the hierarchy it works in.
	basicReads = []Permission{PermOrgRead, PermBusinessUnitRead, PermTeamRead, PermEnvironmentRead}
	// authorityReads lets a principal see what agents may do (M4): grants,
	// guardrails, budgets, packages and policies.
	authorityReads = []Permission{PermGrantRead, PermGuardrailsRead, PermBudgetRead, PermPackageRead, PermPolicyRead}
	// boundaryReads lets a principal see how actions reach targets (M6):
	// gateways, connections and the kill switch.
	boundaryReads = []Permission{PermGatewayRead, PermConnectionRead, PermContainmentRead}
)

func with(ps ...[]Permission) []Permission {
	var out []Permission
	for _, p := range ps {
		for _, x := range p {
			if !slices.Contains(out, x) {
				out = append(out, x)
			}
		}
	}
	return out
}

// roles are the default roles. Platform administration (Org Admin) never
// implies business approval, policy publication or restricted evidence
// access (F583, T-043): those come only from their own roles.
var roles = []Role{
	{
		Name: RoleOrgAdmin, Title: "Org Admin", Scopes: orgScope,
		Description: "Administers the organization: hierarchy, users, invitations, roles and service accounts; imports tool packages and registers the org's package-signing keys. Sets the Agent Waitlist's escalation chains and settings. Reads evidence. Cannot approve actions or see approval requests, restore suspended agents, publish policies, activate packages, issue grants, change guardrails, manage gateways and connections, engage the kill switch, resolve unknown outcomes, export evidence packs, set retention or capture, or read restricted evidence.",
		Permissions: with(basicReads, []Permission{
			PermOrgUpdate, PermBusinessUnitManage, PermTeamManage, PermTeamMembersManage, PermEnvironmentManage,
			PermUserRead, PermUserManage, PermInvitationRead, PermInvitationManage, PermRoleRead, PermRoleBind,
			PermServiceAccountRead, PermServiceAccountManage, PermAuditRead, PermAgentRead, PermRunRead,
			PermWaitlistRead, PermWaitlistManage, PermIssuerRead, PermIssuerManage, PermFactRead, PermPackageImport,
			PermPackageKeyManage, PermNotificationRead, PermNotificationManage, PermEvidenceRead,
		}, authorityReads, boundaryReads),
	},
	{
		Name: RoleSecurityAdmin, Title: "Security Admin", Scopes: orgScope,
		Description: "Watches and contains: reads users, roles, audit and approval requests, disables compromised users and service accounts, revokes grants, responds to incidents, sets the Agent Waitlist's escalation chains and settings, restores suspended agents with a security key, resolves unknown outcomes and exports evidence packs (human only).",
		Permissions: with(basicReads, []Permission{
			PermUserRead, PermUserManage, PermRoleRead, PermInvitationRead, PermServiceAccountRead,
			PermServiceAccountManage, PermAuditRead, PermAgentRead, PermIncidentRespond, PermRunRead, PermRunManage,
			PermWaitlistRead, PermWaitlistManage, PermApprovalRead, PermAgentRestore, PermIssuerRead, PermGrantRevoke,
			PermFactRead, PermNotificationRead, PermNotificationManage, PermEvidenceRead, PermTransactionReconcile,
			PermEvidenceExport,
		}, authorityReads, boundaryReads),
	},
	{
		Name: RoleAgentOwner, Title: "Agent Owner", Scopes: anyScope,
		Description: "Owns agents in scope and is accountable for them; sees their approval requests and can revoke their grants but not issue them.",
		Permissions: with(basicReads, []Permission{
			PermAgentRead, PermAgentManage, PermRunRead, PermRunStart, PermRunManage, PermWaitlistRead, PermAgentEnroll,
			PermGrantRevoke, PermApprovalRead, PermEvidenceRead,
		}, authorityReads),
	},
	{
		Name: RolePolicyAuthor, Title: "Policy Author", Scopes: anyScope,
		Description: "Drafts policies and grants in scope; cannot publish them.",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermPolicyAuthor, PermFactRead}, authorityReads),
	},
	{
		Name: RolePolicyPublisher, Title: "Policy Publisher", Scopes: anyScope,
		Description: "Publishes reviewed policies, changes guardrails, activates imported tool packages and registers fact providers in scope (human only). Cannot author policies or import packages.",
		Permissions: with(basicReads, []Permission{
			PermAgentRead, PermPolicyPublish, PermGuardrailsManage, PermPackageActivate, PermFactRead,
			PermFactProviderManage, PermServiceAccountRead, PermWaitlistRead,
		}, authorityReads),
	},
	{
		Name: RoleApprover, Title: "Approver", Scopes: anyScope,
		Description: "Approves held actions in scope with a security key, or declines them (human only); sees the approval requests and waitlist entries routed to them.",
		Permissions: with(basicReads, []Permission{PermApprovalRespond, PermApprovalRead, PermWaitlistRead}),
	},
	{
		Name: RoleResponder, Title: "Responder", Scopes: anyScope,
		Description: "Investigates and contains incidents in scope, and restores suspended agents with a security key (human only).",
		Permissions: with(basicReads, []Permission{
			PermAgentRead, PermIncidentRespond, PermRunRead, PermRunManage, PermGrantRead, PermGrantRevoke,
			PermConnectionRead, PermContainmentRead, PermWaitlistRead, PermAgentRestore, PermEvidenceRead,
		}),
	},
	{
		Name: RoleAuditor, Title: "Auditor", Scopes: orgScope,
		Description: "Reads configuration, audit and evidence, restricted evidence included, and exports evidence packs (human only); changes nothing.",
		Permissions: with(basicReads, []Permission{
			PermUserRead, PermRoleRead, PermInvitationRead, PermServiceAccountRead, PermAuditRead,
			PermAgentRead, PermEvidenceReadRestricted, PermRunRead, PermWaitlistRead, PermIssuerRead, PermFactRead,
			PermNotificationRead, PermApprovalRead, PermEvidenceRead, PermEvidenceExport,
		}, authorityReads, boundaryReads),
	},
	{
		Name: RoleDeveloper, Title: "Developer", Scopes: anyScope,
		Description: "Builds agents in scope.",
		Permissions: with(basicReads, []Permission{
			PermAgentRead, PermRunRead, PermRunStart, PermConnectionRead, PermEvidenceRead,
		}, authorityReads),
	},
	{
		Name: RoleViewer, Title: "Viewer", Scopes: anyScope,
		Description: "Sees the hierarchy in scope.",
		Permissions: with(basicReads),
	},
	{
		Name: RoleRunLauncher, Title: "Run Launcher", Scopes: anyScope,
		Description: "Starts runs in scope for users who present a fresh token from the identity provider (for example a service acting for a signed-in user). The token proves who is represented and grants nothing.",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermRunRead, PermRunStart, PermRunRepresent, PermGrantRead}),
	},
	{
		Name: RoleAgentAdmitter, Title: "Agent Admitter", Scopes: anyScope,
		Description: "Confirms the key fingerprints of new instances of agents in scope that they own or back up (human only). Holding the role alone admits nothing: the admitter must be the agent's owner or backup owner.",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermWaitlistRead, PermAgentAdmit}),
	},
	{
		Name: RoleIdentityPublisher, Title: "Identity Publisher", Scopes: anyScope,
		Description: "Activates proposed or widened trusted-issuer entries in scope after reviewing what they widen (human only). Cannot propose them.",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermIssuerRead, PermIssuerActivate}),
	},
	{
		Name: RoleGrantIssuer, Title: "Grant Issuer", Scopes: anyScope,
		Description: "Issues, revises and revokes grants to agents in scope (human only). Every grant must still fit inside the guardrails, which the issuer cannot change.",
		Permissions: with(basicReads, []Permission{
			PermAgentRead, PermRunRead, PermGrantIssue, PermGrantRevoke, PermFactRead, PermWaitlistRead,
		}, authorityReads),
	},
	{
		Name: RoleFactProvider, Title: "Fact Provider", Scopes: orgScope,
		Description: "For the service account a fact provider is registered with: lets it report facts. Holding the role alone writes nothing: each fact is accepted only from the service account of the provider registered for it.",
		Permissions: with(basicReads, []Permission{PermFactWrite}),
	},
	{
		Name: RoleGatewayAdmin, Title: "Gateway Admin", Scopes: orgScope,
		Description: "Enrolls and revokes gateways, registers connections and their route modes, and seals target credentials (human only). Weakening changes are audited and reported to org admins.",
		Permissions: with(basicReads, []Permission{
			PermGatewayManage, PermConnectionManage, PermCredentialSeal, PermAgentRead,
		}, authorityReads, boundaryReads),
	},
	{
		Name: RoleEmergency, Title: "Emergency Responder", Scopes: orgScope,
		Description: "Engages the org kill switch with a step-up, and proposes or confirms a restore, which needs a second person with a different security key (human only).",
		Permissions: with(basicReads, []Permission{PermContainmentKillSwitch}, boundaryReads),
	},
	{
		Name: RoleReconciler, Title: "Reconciler", Scopes: anyScope,
		Description: "Owns unknown outcomes in scope, for the operations or finance people who know whether an effect happened: sees the reconciliation entries routed to them in the Agent Waitlist, records them as occurred, releases them on the page with a security key, requests verifications and links compensating transactions (human only).",
		Permissions: with(basicReads, []Permission{
			PermTransactionReconcile, PermEvidenceRead, PermRunRead, PermAgentRead, PermWaitlistRead,
		}),
	},
	{
		Name: RoleRecordsManager, Title: "Records Manager", Scopes: orgScope,
		Description: "Sets what evidence is kept and captured: retention policies, legal holds and payload capture profiles (human only). Cannot read captured payloads.",
		Permissions: with(basicReads, []Permission{PermEvidenceRetentionManage, PermEvidenceCaptureManage, PermEvidenceRead}),
	},
}

// Roles returns the default roles in a stable order.
func Roles() []Role {
	out := make([]Role, len(roles))
	for i, r := range roles {
		r.Permissions = slices.Clone(r.Permissions)
		r.Scopes = slices.Clone(r.Scopes)
		out[i] = r
	}
	return out
}

// LookupRole returns the role named n.
func LookupRole(n RoleName) (Role, bool) {
	i := slices.IndexFunc(roles, func(r Role) bool { return r.Name == n })
	if i < 0 {
		return Role{}, false
	}
	return roles[i], true
}

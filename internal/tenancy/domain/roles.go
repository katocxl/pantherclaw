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
	// G0 M8 release controls (HR-207).
	RoleCodeReviewer    RoleName = "code_reviewer"
	RoleReleaseApprover RoleName = "release_approver"
	// G0 M10 SOAR requests (D4, HR-251).
	RoleSOARIntegration RoleName = "soar_integration"
	// G0 M11 part 2 governed automations and fleet governance (D12).
	RoleAutomationAuthor    RoleName = "automation_author"
	RoleAutomationPublisher RoleName = "automation_publisher"
	RoleAutomationOperator  RoleName = "automation_operator"
	RoleFleetManager        RoleName = "fleet_manager"
	// G0 M14 AuthZEN enforcement points (D5).
	RoleEnforcementPoint RoleName = "enforcement_point"
	// G0 M18 delegated administration (D152, F584).
	RoleScopeAdmin RoleName = "scope_admin"
	// G0 M24 device scans (D236, HR-589).
	RoleScanner RoleName = "scanner"
)

// Role is a named set of permissions and the scope types it may be bound at.
type Role struct {
	Name        RoleName
	Title       string
	Description string
	Permissions []Permission
	Scopes      []ScopeType
	// ServiceOnly roles are bound only to service accounts (G0 M10 D4).
	ServiceOnly bool
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
	// teamScope is a team or one of its environments: the release roles
	// review and release one team's changes (G0 M8, HR-207). A claimed
	// agent always has a team and an environment, so its requests can
	// always reach them.
	teamScope = []ScopeType{ScopeTeam, ScopeEnvironment}
	// belowOrgScope is any scope inside the organization but the org
	// itself: a Scope Admin administers a part of the org (G0 M18 D152).
	belowOrgScope = []ScopeType{ScopeBusinessUnit, ScopeTeam, ScopeEnvironment}
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
		Description: "Administers the organization: hierarchy, users, invitations, roles and service accounts; imports tool packages and registers the org's package-signing keys; asks for policy exceptions, which only policy publishers confirm. Sets the Agent Waitlist's escalation chains and settings. Reads evidence, coverage, automations, detections, incidents, cases, exposure, posture, operations, search, integrations and the MCP server catalogue, and simulates policy versions over recorded decisions. Registers AuthZEN enforcement points (human only) and reads the runs peer agents made for requesters. Proposes changes to the org's own identity providers, each confirmed by a second person (human only), and reads them. Cannot approve actions or see approval requests, restore suspended agents, publish policies, activate packages, issue grants, change guardrails, manage gateways and connections, engage the kill switch, resolve unknown outcomes, export evidence packs, exclude routes from coverage, set retention or capture, or read restricted evidence.",
		Permissions: with(basicReads, []Permission{
			PermOrgUpdate, PermBusinessUnitManage, PermTeamManage, PermTeamMembersManage, PermEnvironmentManage,
			PermUserRead, PermUserManage, PermInvitationRead, PermInvitationManage, PermRoleRead, PermRoleBind,
			PermServiceAccountRead, PermServiceAccountManage, PermAuditRead, PermAgentRead, PermRunRead,
			PermWaitlistRead, PermWaitlistManage, PermIssuerRead, PermIssuerManage, PermFactRead, PermPackageImport,
			PermPackageKeyManage, PermNotificationRead, PermNotificationManage, PermEvidenceRead, PermCoverageRead, PermRedteamRead,
			PermPolicyExceptionRequest,
			PermGitHubIdentityManage, PermGitHubIdentityProve, PermGitHubScanRun, PermPolicySimulate, PermAutomationRead,
			PermEnforcementPointManage, PermA2APeerRunRead, PermIdentityProviderRead, PermIdentityProviderManage,
			PermCatalogRead,
		}, authorityReads, boundaryReads, reflexReads),
	},
	{
		Name: RoleSecurityAdmin, Title: "Security Admin", Scopes: orgScope,
		Description: "Watches and contains: reads users, roles, audit and approval requests, disables compromised users and service accounts, revokes grants, responds to incidents, sets the Agent Waitlist's escalation chains and settings, restores suspended agents with a security key, resolves unknown outcomes, exports evidence packs, sets the change windows (human only), excludes routes from coverage and acknowledges its findings (human only), reassesses coverage, and manages detections, incidents, cases, posture findings, SIEM export and Shared Signals, protected-change settings and compromised publishers (human only), AuthZEN enforcement points (human only), external policy checks (human only), the org's customer consequence rules, each confirmed by a second person (human only), and the MCP server catalogue; reads automations, the runs peer agents made for requesters and the org's identity providers.",
		Permissions: with(basicReads, []Permission{
			PermUserRead, PermUserManage, PermRoleRead, PermInvitationRead, PermServiceAccountRead,
			PermServiceAccountManage, PermAuditRead, PermAgentRead, PermIncidentRespond, PermRunRead, PermRunManage,
			PermWaitlistRead, PermWaitlistManage, PermApprovalRead, PermAgentRestore, PermIssuerRead, PermGrantRevoke,
			PermFactRead, PermNotificationRead, PermNotificationManage, PermEvidenceRead, PermTransactionReconcile,
			PermEvidenceExport, PermReleaseWindowManage, PermGitHubScanRun, PermCoverageRead, PermCoverageManage, PermCoverageReassess, PermRedteamRead,
		}, authorityReads, boundaryReads, reflexReads, reflexManage, []Permission{
			PermAutomationRead, PermProtectedChangeManage, PermPublisherCompromise, PermEnforcementPointManage, PermA2APeerRunRead,
			PermExternalCheckManage,
			PermConsequenceRuleManage,
			PermIdentityProviderRead,
			PermCatalogRead, PermCatalogManage,
		}),
	},
	{
		Name: RoleAgentOwner, Title: "Agent Owner", Scopes: anyScope,
		Description: "Owns agents in scope and is accountable for them; sees their approval requests and can revoke their grants but not issue them; reads and reassesses their coverage, and runs them in the containment sandbox.",
		Permissions: with(basicReads, []Permission{
			PermAgentRead, PermAgentManage, PermRunRead, PermRunStart, PermRunManage, PermWaitlistRead, PermAgentEnroll,
			PermGrantRevoke, PermApprovalRead, PermEvidenceRead, PermCoverageRead, PermCoverageReassess, PermSandboxRun, PermRedteamRun, PermRedteamRead,
		}, authorityReads),
	},
	{
		Name: RolePolicyAuthor, Title: "Policy Author", Scopes: anyScope,
		Description: "Drafts policies and grants in scope, simulates policy versions over recorded decisions and asks for policy exceptions (human only); cannot publish them.",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermPolicyAuthor, PermPolicySimulate, PermFactRead, PermPolicyExceptionRequest}, authorityReads),
	},
	{
		Name: RolePolicyPublisher, Title: "Policy Publisher", Scopes: anyScope,
		Description: "Publishes reviewed policies, asks for, confirms and revokes policy exceptions, changes guardrails, activates imported tool packages and registers fact providers in scope (human only); simulates policy versions over recorded decisions. Cannot author policies or import packages.",
		Permissions: with(basicReads, []Permission{
			PermAgentRead, PermPolicyPublish, PermPolicySimulate, PermGuardrailsManage, PermPackageActivate, PermFactRead,
			PermFactProviderManage, PermServiceAccountRead, PermWaitlistRead, PermPolicyExceptionRequest,
		}, authorityReads),
	},
	{
		Name: RoleApprover, Title: "Approver", Scopes: anyScope,
		Description: "Approves held actions in scope with a security key, or declines them (human only); sees the approval requests and waitlist entries routed to them.",
		Permissions: with(basicReads, []Permission{PermApprovalRespond, PermApprovalRead, PermWaitlistRead, PermGitHubIdentityProve}),
	},
	{
		Name: RoleResponder, Title: "Responder", Scopes: anyScope,
		Description: "Investigates and contains incidents in scope, manages incidents, cases and posture findings, and restores suspended agents with a security key (human only).",
		Permissions: with(basicReads, []Permission{
			PermAgentRead, PermIncidentRespond, PermRunRead, PermRunManage, PermGrantRead, PermGrantRevoke,
			PermConnectionRead, PermContainmentRead, PermWaitlistRead, PermAgentRestore, PermEvidenceRead, PermCoverageRead, PermRedteamRead,
		}, reflexReads, []Permission{PermIncidentManage, PermCaseManage, PermPostureManage, PermAutomationRead}),
	},
	{
		Name: RoleAuditor, Title: "Auditor", Scopes: orgScope,
		Description: "Reads configuration, audit and evidence, restricted evidence included, the runs peer agents made for requesters, the org's identity providers and the MCP server catalogue, and exports evidence packs (human only); changes nothing.",
		Permissions: with(basicReads, []Permission{
			PermUserRead, PermRoleRead, PermInvitationRead, PermServiceAccountRead, PermAuditRead,
			PermAgentRead, PermEvidenceReadRestricted, PermRunRead, PermWaitlistRead, PermIssuerRead, PermFactRead,
			PermNotificationRead, PermApprovalRead, PermEvidenceRead, PermEvidenceExport, PermCoverageRead, PermRedteamRead, PermAutomationRead,
			PermA2APeerRunRead, PermIdentityProviderRead, PermCatalogRead,
		}, authorityReads, boundaryReads, reflexReads),
	},
	{
		Name: RoleDeveloper, Title: "Developer", Scopes: anyScope,
		Description: "Builds agents in scope and runs them in the containment sandbox.",
		Permissions: with(basicReads, []Permission{
			PermAgentRead, PermRunRead, PermRunStart, PermConnectionRead, PermEvidenceRead, PermGitHubIdentityProve, PermCoverageRead,
			PermSandboxRun, PermRedteamRun, PermRedteamRead,
		}, authorityReads),
	},
	{
		Name: RoleViewer, Title: "Viewer", Scopes: anyScope,
		Description: "Sees the hierarchy in scope, the operations view and incidents.",
		Permissions: with(basicReads, []Permission{PermOperationsRead, PermIncidentRead, PermAutomationRead}),
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
		Description: "Enrolls and revokes gateways, registers and tests connections and their route modes, and seals target credentials (human only). Weakening changes are audited and reported to org admins.",
		Permissions: with(basicReads, []Permission{
			PermGatewayManage, PermConnectionManage, PermConnectionTest, PermCredentialSeal, PermAgentRead,
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
	{
		Name: RoleCodeReviewer, Title: "Code Reviewer", Scopes: teamScope,
		Description: "Reviews the changes agents want to merge and approves or declines them with a security key (human only). Every approval of an action whose definition names the people it must be independent of excludes the change's author and every author, committer and pusher of its commits, whatever role it asks for.",
		Permissions: with(basicReads, []Permission{PermApprovalRespond, PermApprovalRead, PermWaitlistRead, PermGitHubIdentityProve}),
	},
	{
		Name: RoleReleaseApprover, Title: "Release Approver", Scopes: teamScope,
		Description: "Approves releases, the actions whose predicted or unknown consequence is a deployment, with a security key (human only); a window requirement counts the approval only inside an active change window for the environment. Never the change's reviewer.",
		Permissions: with(basicReads, []Permission{PermApprovalRespond, PermApprovalRead, PermWaitlistRead, PermGitHubIdentityProve}),
	},
	{
		Name: RoleSOARIntegration, Title: "SOAR Integration", Scopes: orgScope, ServiceOnly: true,
		Description: "For the service account of a SOAR or response tool: reads incidents and the kill switch's state and asks for narrow containment of a run, agent, grant or connection. Never engages the kill switch, lifts a control or restores anything (HR-251). Bound only to service accounts.",
		Permissions: with(basicReads, []Permission{PermResponseRequest, PermIncidentRead, PermContainmentRead}),
	},
	{
		Name: RoleAutomationAuthor, Title: "Automation Author", Scopes: anyScope,
		Description: "Creates automations and authors their versions, manages inbound event sources and automation destinations, asks for a version to be enabled, and narrows, pauses, resumes, retires or revokes the authority of automations in scope (human only); opens the work queue. Cannot confirm an enabling: that needs an Automation Publisher.",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermAutomationRead, PermAutomationManage, PermAutomationEndpointsManage, PermOperationsRead}, authorityReads),
	},
	{
		Name: RoleAutomationPublisher, Title: "Automation Publisher", Scopes: anyScope,
		Description: "Confirms the enabling of an automation version and its issuance ceiling with a security key, and decides automation gates (human only); opens the work queue. Confirming also needs every permission the version's steps use where they act, such as grant.issue and run.start on its agents. Cannot author or change automations.",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermAutomationRead, PermAutomationPublish, PermAutomationApprove, PermOperationsRead}, authorityReads),
	},
	{
		Name: RoleAutomationOperator, Title: "Automation Operator", Scopes: anyScope,
		Description: "Starts manual executions of automations in scope and decides automation gates (human only); opens the work queue.",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermAutomationRead, PermAutomationRun, PermAutomationApprove, PermOperationsRead}),
	},
	{
		Name: RoleFleetManager, Title: "Fleet Manager", Scopes: anyScope,
		Description: "Promotes agents' operations for production after their readiness checks pass, and manages fleet cohorts and their grant baselines (human only).",
		Permissions: with(basicReads, []Permission{PermAgentRead, PermAgentPromote, PermCohortManage}, authorityReads),
	},
	{
		Name: RoleEnforcementPoint, Title: "Enforcement Point", Scopes: orgScope, ServiceOnly: true,
		Description: "For the service account of an enforcement point in front of an API or MCP server: asks the AuthZEN decision endpoint whether an agent's request may go through. Holding the role alone decides nothing: the service account must be the subject of an active enforcement point bound to the connection. Bound only to service accounts.",
		Permissions: with(basicReads, []Permission{PermAuthZENEvaluate}),
	},
	{
		Name: RoleScopeAdmin, Title: "Scope Admin", Scopes: belowOrgScope,
		Description: "Administers a business unit, team or environment: reads its users and role bindings, and binds or unbinds roles there or below, but only roles it holds itself at that scope or above, Scope Admin included. Never binds an organization-scope role, invites people or manages service accounts.",
		Permissions: with(basicReads, []Permission{PermRoleBind, PermRoleRead, PermUserRead}),
	},
	{
		Name: RoleScanner, Title: "Scanner", Scopes: anyScope, ServiceOnly: true,
		Description: "For the service account of a device scan: submits scan findings for its scope and nothing else (HR-589). Beyond its own org, a key taken from a laptop reads nothing: not business units, teams or environments. Bound only to service accounts.",
		Permissions: []Permission{PermOrgRead, PermAgentScanSubmit},
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

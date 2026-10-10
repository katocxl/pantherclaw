// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"strings"
)

// Permission names one capability. Every RPC declares the permission it
// requires ("// permission: <name>" in its proto, BUILD_GUIDE §3.2); a test
// checks each declared name against this catalog.
type Permission string

// Pseudo-permissions used only in RPC declarations, never in roles.
const (
	// PermPublic marks procedures callable without authentication.
	PermPublic Permission = "public"
	// PermAuthenticated marks procedures any authenticated user or service
	// account may call (for example "who am I").
	PermAuthenticated Permission = "authenticated"
)

// Tenancy and access permissions (M2).
const (
	PermOrgRead              Permission = "org.read"
	PermOrgUpdate            Permission = "org.update"
	PermBusinessUnitRead     Permission = "business_unit.read"
	PermBusinessUnitManage   Permission = "business_unit.manage"
	PermTeamRead             Permission = "team.read"
	PermTeamManage           Permission = "team.manage"
	PermTeamMembersManage    Permission = "team.members.manage"
	PermEnvironmentRead      Permission = "environment.read"
	PermEnvironmentManage    Permission = "environment.manage"
	PermUserRead             Permission = "user.read"
	PermUserManage           Permission = "user.manage"
	PermInvitationRead       Permission = "invitation.read"
	PermInvitationManage     Permission = "invitation.manage"
	PermRoleRead             Permission = "role.read"
	PermRoleBind             Permission = "role.bind"
	PermServiceAccountRead   Permission = "service_account.read"
	PermServiceAccountManage Permission = "service_account.manage"
	PermAuditRead            Permission = "audit.read"
)

// Notification permissions (M5): channels, their secrets and delivery
// health. Only org-scope roles hold them.
const (
	PermNotificationRead   Permission = "notification.read"
	PermNotificationManage Permission = "notification.manage"
)

// Permissions of later milestones. They are defined now so that the default
// roles and the separation-of-duties tests cover them before their RPCs
// exist (F581, F583).
const (
	PermAgentRead              Permission = "agent.read"               // M3
	PermAgentManage            Permission = "agent.manage"             // M3
	PermPolicyAuthor           Permission = "policy.author"            // M4
	PermPolicyPublish          Permission = "policy.publish"           // M4/M11, human only
	PermApprovalRespond        Permission = "approval.respond"         // M5, human only
	PermIncidentRespond        Permission = "incident.respond"         // M10
	PermEvidenceReadRestricted Permission = "evidence.read_restricted" // M7, human only
)

// Run and waitlist permissions (M3). run.represent lets a launcher present
// an RFC 8693 subject token to start a run for another user (HR-146).
const (
	PermRunRead      Permission = "run.read"
	PermRunStart     Permission = "run.start"
	PermRunRepresent Permission = "run.represent"
	PermRunManage    Permission = "run.manage"
	PermWaitlistRead Permission = "waitlist.read"
)

// Approval and waitlist permissions (G0 M5 part 2). approval.read shows
// approval requests and their content; it is not on Org Admin, which stays
// out of approvals (F583). waitlist.manage changes escalation chains and
// waitlist settings. agent.restore decides restorations of suspended agents
// and is human only (decision 11).
const (
	PermApprovalRead   Permission = "approval.read"
	PermWaitlistManage Permission = "waitlist.manage"
	PermAgentRestore   Permission = "agent.restore"
)

// Grant, guardrail, budget, fact, package and policy permissions (G0 M4
// part 2). grant.issue (decision 7), guardrails.manage (HR-161),
// fact.provider.manage (HR-160) and package.activate are human only.
// fact.write is held by the service account a fact provider is bound to:
// holding it alone writes nothing, because each fact is accepted only from
// its provider's own service account.
const (
	PermGrantRead          Permission = "grant.read"
	PermGrantIssue         Permission = "grant.issue"
	PermGrantRevoke        Permission = "grant.revoke"
	PermGuardrailsRead     Permission = "guardrails.read"
	PermGuardrailsManage   Permission = "guardrails.manage"
	PermBudgetRead         Permission = "budget.read"
	PermFactRead           Permission = "fact.read"
	PermFactProviderManage Permission = "fact.provider.manage"
	PermFactWrite          Permission = "fact.write"
	PermPackageRead        Permission = "package.read"
	PermPackageImport      Permission = "package.import"
	PermPackageActivate    Permission = "package.activate"
	PermPolicyRead         Permission = "policy.read"
)

// PermPackageKeyManage registers and revokes the org's package-signing keys
// (HR-162, Team edition). It sits on the Org Admin role, which service
// accounts may hold, so it is not in the human-only catalog: the use case
// lets only a person register a key, while revoking one (which only removes
// trust) is open to any holder.
const PermPackageKeyManage Permission = "package.key.manage"

// Workload identity permissions (M3). agent.admit (confirming an instance's
// fingerprint, HR-094) and identity.issuer.activate (switching on a
// trusted-issuer revision, HR-141) are human only.
const (
	PermAgentEnroll    Permission = "agent.enroll"
	PermAgentAdmit     Permission = "agent.admit"
	PermIssuerRead     Permission = "identity.issuer.read"
	PermIssuerManage   Permission = "identity.issuer.manage"
	PermIssuerActivate Permission = "identity.issuer.activate"
)

// Gateway permissions are held only by authenticated gateways (M6 mTLS,
// HR-181), never by users, service accounts or roles. gateway.enroll is
// authenticated by the enrollment token in the request itself (HR-180).
const (
	PermGatewayAuthorize Permission = "gateway.authorize"
	PermGatewayDispatch  Permission = "gateway.dispatch"
	PermGatewayObserve   Permission = "gateway.observe"
	PermGatewayEnroll    Permission = "gateway.enroll"
	PermGatewaySync      Permission = "gateway.sync"
)

// Gateway, connection, credential and containment administration (G0 M6).
// gateway.manage, connection.manage and credential.seal are human only
// (HR-183): they decide where target credentials go and whether actions are
// enforced. containment.killswitch is human only and also needs a step-up
// on the emergency-stop page (HR-113).
const (
	PermGatewayRead           Permission = "gateway.read"
	PermGatewayManage         Permission = "gateway.manage"
	PermConnectionRead        Permission = "connection.read"
	PermConnectionManage      Permission = "connection.manage"
	PermCredentialSeal        Permission = "credential.seal" //nolint:gosec // G101: a permission name, not a credential
	PermContainmentRead       Permission = "containment.read"
	PermContainmentKillSwitch Permission = "containment.killswitch"
)

// Evidence and reconciliation permissions (G0 M7, Contracts → Permissions).
// evidence.read covers the explorer, checkpoints, proofs, anchors, bundles,
// replay outcomes and pack metadata, scoped like run.read. Resolving unknown
// outcomes, exporting packs, setting retention and configuring capture are
// human only; whoever configures capture cannot read it
// (evidence.read_restricted stays with the Auditor).
const (
	PermEvidenceRead            Permission = "evidence.read"
	PermEvidenceExport          Permission = "evidence.export"
	PermEvidenceRetentionManage Permission = "evidence.retention.manage"
	PermEvidenceCaptureManage   Permission = "evidence.capture.manage"
	PermTransactionReconcile    Permission = "transaction.reconcile"
	PermGatewayVerify           Permission = "gateway.verify" // gateways only: lease and report verifications (HR-190)
)

// Workload permissions are held only by PAP/1-authenticated workloads
// (WorkloadService), never by users, service accounts or roles.
const (
	PermWorkloadEnroll Permission = "workload.enroll"
	PermWorkloadToken  Permission = "workload.token"
	PermWorkloadRun    Permission = "workload.run"
	// PermWorkloadDelegate lets a workload delegate part of its run's grant
	// to a child run (M4, HR-047).
	PermWorkloadDelegate Permission = "workload.delegate"
)

// catalog lists every grantable permission.
var catalog = []Permission{
	PermOrgRead, PermOrgUpdate,
	PermBusinessUnitRead, PermBusinessUnitManage,
	PermTeamRead, PermTeamManage, PermTeamMembersManage,
	PermEnvironmentRead, PermEnvironmentManage,
	PermUserRead, PermUserManage,
	PermInvitationRead, PermInvitationManage,
	PermRoleRead, PermRoleBind,
	PermServiceAccountRead, PermServiceAccountManage,
	PermAuditRead,
	PermNotificationRead, PermNotificationManage,
	PermAgentRead, PermAgentManage,
	PermRunRead, PermRunStart, PermRunRepresent, PermRunManage,
	PermWaitlistRead, PermWaitlistManage, PermApprovalRead, PermAgentRestore,
	PermAgentEnroll, PermAgentAdmit,
	PermIssuerRead, PermIssuerManage, PermIssuerActivate,
	PermPolicyAuthor, PermPolicyPublish, PermPolicyRead,
	PermGrantRead, PermGrantIssue, PermGrantRevoke,
	PermGuardrailsRead, PermGuardrailsManage, PermBudgetRead,
	PermFactRead, PermFactProviderManage, PermFactWrite,
	PermPackageRead, PermPackageImport, PermPackageActivate, PermPackageKeyManage,
	PermApprovalRespond, PermIncidentRespond, PermEvidenceReadRestricted,
	PermGatewayRead, PermGatewayManage, PermConnectionRead, PermConnectionManage, PermCredentialSeal,
	PermContainmentRead, PermContainmentKillSwitch,
	PermEvidenceRead, PermEvidenceExport, PermEvidenceRetentionManage, PermEvidenceCaptureManage,
	PermTransactionReconcile,
}

// humanOnly permissions can never be exercised by a service account or an
// API key, whatever their bindings say (ARCHITECTURE §10: "pck_ keys never
// able to approve"; F583).
var humanOnly = []Permission{
	PermApprovalRespond, PermPolicyPublish, PermEvidenceReadRestricted, PermAgentAdmit, PermIssuerActivate,
	PermGrantIssue, PermGuardrailsManage, PermFactProviderManage, PermPackageActivate,
	PermGatewayManage, PermConnectionManage, PermCredentialSeal, PermContainmentKillSwitch, PermAgentRestore,
	PermTransactionReconcile, PermEvidenceExport, PermEvidenceRetentionManage, PermEvidenceCaptureManage,
}

// Catalog returns every grantable permission in a stable order.
func Catalog() []Permission { return slices.Clone(catalog) }

// Known reports whether p is a grantable permission.
func (p Permission) Known() bool { return slices.Contains(catalog, p) }

// HumanOnly reports whether only a human may hold p.
func (p Permission) HumanOnly() bool { return slices.Contains(humanOnly, p) }

// gatewayOnly permissions belong to authenticated gateways. gateway.read
// and gateway.manage are ordinary permissions for people.
var gatewayOnly = []Permission{
	PermGatewayAuthorize, PermGatewayDispatch, PermGatewayObserve, PermGatewayEnroll, PermGatewaySync, PermGatewayVerify,
}

// Gateway reports whether p belongs to gateways.
func (p Permission) Gateway() bool { return slices.Contains(gatewayOnly, p) }

// Workload reports whether p belongs to PAP/1-authenticated workloads.
func (p Permission) Workload() bool { return strings.HasPrefix(string(p), "workload.") }

// declarableOnly are requirements an RPC may declare that no role grants.
var declarableOnly = []Permission{
	PermPublic, PermAuthenticated, PermGatewayAuthorize, PermGatewayDispatch, PermGatewayObserve, PermGatewayEnroll,
	PermGatewaySync, PermGatewayVerify, PermWorkloadEnroll, PermWorkloadToken, PermWorkloadRun, PermWorkloadDelegate,
}

// Declarable reports whether an RPC may declare p as its requirement.
func (p Permission) Declarable() bool { return slices.Contains(declarableOnly, p) || p.Known() }

// APIKeyScopable reports whether p may appear in an API key's scopes.
func (p Permission) APIKeyScopable() bool { return p.Known() && !p.HumanOnly() }

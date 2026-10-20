// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"strings"
)

// UI phase permissions (G0 UI D8, D9, D15, D21).
//
//   - entitlements.read: read the org's plan, limits and usage.
//   - onboarding.read: read the org's onboarding progress.
//
// Account-session requirements are declarable only, never granted by a
// role: they belong to the signed-in account itself, not to a membership
// (HR-350).
//
//   - orgs.create: create an organization (account browser sessions only).
//   - orgs.list_mine: list the account's organizations.
//   - invitations.accept: accept an invitation in the browser (account and
//     org browser sessions).
const (
	PermEntitlementsRead  Permission = "entitlements.read"
	PermOnboardingRead    Permission = "onboarding.read"
	PermOrgsCreate        Permission = "orgs.create"
	PermOrgsListMine      Permission = "orgs.list_mine"
	PermInvitationsAccept Permission = "invitations.accept"
	// PermBillingManage starts checkouts and opens the billing portal
	// through the billing extension (D70); Org Admin only.
	PermBillingManage Permission = "billing.manage"
)

// uiCatalog are the UI phase's grantable permissions in catalog order.
var uiCatalog = []Permission{PermEntitlementsRead, PermOnboardingRead, PermBillingManage}

// accountOnly are the account-session requirements (declarable only).
var accountOnly = []Permission{PermOrgsCreate, PermOrgsListMine, PermInvitationsAccept}

// The UI phase's grants (D35): every role a person holds reads the org's
// plan; the roles that run onboarding also read its progress. Service-only
// roles get neither, and neither do the roles service accounts hold to do
// one job (run launching, fact providing).
var (
	planReaders = []RoleName{
		RoleOrgAdmin, RoleSecurityAdmin, RoleAgentOwner, RolePolicyAuthor, RolePolicyPublisher, RoleApprover,
		RoleResponder, RoleAuditor, RoleDeveloper, RoleViewer, RoleAgentAdmitter, RoleIdentityPublisher,
		RoleGrantIssuer, RoleGatewayAdmin, RoleEmergency, RoleReconciler, RoleRecordsManager, RoleCodeReviewer,
		RoleReleaseApprover, RoleAutomationAuthor, RoleAutomationPublisher, RoleAutomationOperator, RoleFleetManager,
	}
	onboardingReaders = []RoleName{RoleOrgAdmin, RoleSecurityAdmin, RoleAgentOwner, RoleDeveloper}
)

func init() {
	for i := range roles {
		r := &roles[i]
		var reads []string
		if slices.Contains(planReaders, r.Name) {
			r.Permissions = append(r.Permissions, PermEntitlementsRead)
			reads = append(reads, "plan")
		}
		if slices.Contains(onboardingReaders, r.Name) {
			r.Permissions = append(r.Permissions, PermOnboardingRead)
			reads = append(reads, "onboarding progress")
		}
		if len(reads) > 0 {
			r.Description += " Reads the org's " + strings.Join(reads, " and ") + "."
		}
		if r.Name == RoleOrgAdmin {
			r.Permissions = append(r.Permissions, PermBillingManage)
			r.Description += " Manages the org's subscription (checkout and billing portal)."
		}
	}
}

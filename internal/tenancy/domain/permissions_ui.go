// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

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
)

// uiCatalog are the UI phase's grantable permissions in catalog order.
var uiCatalog = []Permission{PermEntitlementsRead, PermOnboardingRead}

// accountOnly are the account-session requirements (declarable only).
var accountOnly = []Permission{PermOrgsCreate, PermOrgsListMine, PermInvitationsAccept}

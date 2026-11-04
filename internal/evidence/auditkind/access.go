// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "access.". The ledger stores each as "audit." + the kind.
const (
	AccessApiKeyCreated = "access.api_key_created"
	AccessApiKeyRevoked = "access.api_key_revoked"
	AccessBootstrapInvitationCreated = "access.bootstrap_invitation_created"
	AccessInvitationAccepted = "access.invitation_accepted"
	AccessInvitationCreated = "access.invitation_created"
	AccessInvitationRefused = "access.invitation_refused"
	AccessInvitationRevoked = "access.invitation_revoked"
	AccessRoleBound = "access.role_bound"
	AccessRoleUnbound = "access.role_unbound"
	AccessServiceAccountCreated = "access.service_account_created"
	AccessServiceAccountDisabled = "access.service_account_disabled"
	AccessServiceAccountEnabled = "access.service_account_enabled"
	AccessServiceAccountKeyAdded = "access.service_account_key_added"
	AccessServiceAccountKeyRevoked = "access.service_account_key_revoked"
	AccessServiceAccountUpdated = "access.service_account_updated"
	AccessUserCreated = "access.user_created"
	AccessUserDisabled = "access.user_disabled"
	AccessUserEnabled = "access.user_enabled"
)

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "scim.". The ledger stores each as "audit." + the kind.
const (
	ScimGroupChanged = "scim.group_changed"
	ScimGroupCreated = "scim.group_created"
	ScimGroupDeleted = "scim.group_deleted"
	ScimGroupRoleMappingAdded = "scim.group_role_mapping_added"
	ScimGroupRoleMappingRemoved = "scim.group_role_mapping_removed"
	ScimPartsDropped = "scim.parts_dropped"
	ScimTokenActivated = "scim.token_activated"
	ScimTokenCreated = "scim.token_created"
	ScimTokenRevoked = "scim.token_revoked"
	ScimUserChanged = "scim.user_changed"
	ScimUserCreated = "scim.user_created"
	ScimUserDeleted = "scim.user_deleted"
	ScimUserDeprovisionRefused = "scim.user_deprovision_refused"
	ScimUserDeprovisioned = "scim.user_deprovisioned"
)

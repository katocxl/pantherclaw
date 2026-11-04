// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "connection.". The ledger stores each as "audit." + the kind.
const (
	ConnectionA2aPinConfirmed = "connection.a2a_pin_confirmed"
	ConnectionCreated = "connection.created"
	ConnectionDriftReported = "connection.drift_reported"
	ConnectionElicitationRefused = "connection.elicitation_refused"
	ConnectionInventoryCovered = "connection.inventory_covered"
	ConnectionInventoryDiscovered = "connection.inventory_discovered"
	ConnectionInventoryDismissed = "connection.inventory_dismissed"
	ConnectionInventoryDrafted = "connection.inventory_drafted"
	ConnectionInventoryListedAgain = "connection.inventory_listed_again"
	ConnectionInventoryNoteAdded = "connection.inventory_note_added"
	ConnectionInventoryVanished = "connection.inventory_vanished"
	ConnectionPostgresManifestConfirmed = "connection.postgres_manifest_confirmed"
	ConnectionQuarantined = "connection.quarantined"
	ConnectionRestored = "connection.restored"
	ConnectionRetired = "connection.retired"
	ConnectionRouteModeChanged = "connection.route_mode_changed"
	ConnectionSealedRevoked = "connection.sealed_revoked"
	ConnectionSealedStored = "connection.sealed_stored"
	ConnectionSecretInPayloadRefused = "connection.secret_in_payload_refused"
	ConnectionTestTokensMinted = "connection.test_tokens_minted"
	ConnectionTested = "connection.tested"
	ConnectionToolDescriptionFlagged = "connection.tool_description_flagged"
	ConnectionUpdated = "connection.updated"
)

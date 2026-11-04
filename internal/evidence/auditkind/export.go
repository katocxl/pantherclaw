// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "export.". The ledger stores each as "audit." + the kind.
const (
	ExportArtifactRemovedHere = "export.artifact_removed_here"
	ExportDestinationActivated = "export.destination_activated"
	ExportDestinationCreated = "export.destination_created"
	ExportDestinationCredentialReplaced = "export.destination_credential_replaced"
	ExportDestinationStateChanged = "export.destination_state_changed"
	ExportPushDelivered = "export.push_delivered"
	ExportPushFailed = "export.push_failed"
	ExportPushRefused = "export.push_refused"
	ExportPushRequested = "export.push_requested"
	ExportRemovalNoticeSent = "export.removal_notice_sent"
	ExportRemovalNoticeUndeliverable = "export.removal_notice_undeliverable"
)

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "ticket.". The ledger stores each as "audit." + the kind.
const (
	TicketCreated = "ticket.created"
	TicketCreatedUnlinked = "ticket.created_unlinked"
	TicketFieldOwnerChanged = "ticket.field_owner_changed"
	TicketLinked = "ticket.linked"
	TicketOpenRequested = "ticket.open_requested"
	TicketOwnedFieldIgnored = "ticket.owned_field_ignored"
	TicketSyncConfigured = "ticket.sync_configured"
	TicketSyncFailed = "ticket.sync_failed"
	TicketSyncSecretRotated = "ticket.sync_secret_rotated"
	TicketSyncStateChanged = "ticket.sync_state_changed"
	TicketWebhookRefused = "ticket.webhook_refused"
)

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "waitlist.". The ledger stores each as "audit." + the kind.
const (
	WaitlistAccessRequestDismissed = "waitlist.access_request_dismissed"
	WaitlistAssigned = "waitlist.assigned"
	WaitlistDeliveryFailing = "waitlist.delivery_failing"
	WaitlistEntryClosed = "waitlist.entry_closed"
	WaitlistEntryExpired = "waitlist.entry_expired"
	WaitlistEntryOpened = "waitlist.entry_opened"
	WaitlistEscalated = "waitlist.escalated"
	WaitlistEscalationChainSet = "waitlist.escalation_chain_set"
	WaitlistRouted = "waitlist.routed"
	WaitlistSettingsUpdated = "waitlist.settings_updated"
	WaitlistUnassigned = "waitlist.unassigned"
)

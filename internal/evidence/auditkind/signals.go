// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "signals.". The ledger stores each as "audit." + the kind.
const (
	SignalsEventReceived           = "signals.event_received"
	SignalsPlaybookActed           = "signals.playbook_acted"
	SignalsPlaybookChanged         = "signals.playbook_changed"
	SignalsPlaybookConfirmed       = "signals.playbook_confirmed"
	SignalsPlaybookDeclined        = "signals.playbook_declined"
	SignalsPlaybookFailed          = "signals.playbook_failed"
	SignalsPlaybookRequested       = "signals.playbook_requested"
	SignalsPlaybookSkipped         = "signals.playbook_skipped"
	SignalsPlaybookVoided          = "signals.playbook_voided"
	SignalsTransmitterActivated    = "signals.transmitter_activated"
	SignalsTransmitterCreated      = "signals.transmitter_created"
	SignalsTransmitterStateChanged = "signals.transmitter_state_changed"
)

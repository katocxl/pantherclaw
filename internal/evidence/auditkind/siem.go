// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "siem.". The ledger stores each as "audit." + the kind.
const (
	SiemDestinationActivated = "siem.destination_activated"
	SiemDestinationCreated = "siem.destination_created"
	SiemDestinationRetried = "siem.destination_retried"
	SiemDestinationSecretRotated = "siem.destination_secret_rotated"
	SiemDestinationSignatureSchemeSet = "siem.destination_signature_scheme_set"
	SiemDestinationStateChanged = "siem.destination_state_changed"
)

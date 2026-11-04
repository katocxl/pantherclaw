// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "evidence.". The ledger stores each as "audit." + the kind.
const (
	EvidenceAnchorFailed           = "evidence.anchor_failed"
	EvidenceCaptureProfileCreated  = "evidence.capture_profile_created"
	EvidenceCaptureProfileDisabled = "evidence.capture_profile_disabled"
	EvidenceIntegrityReset         = "evidence.integrity_reset"
	EvidenceLegalHoldCreated       = "evidence.legal_hold_created"
	EvidenceLegalHoldReleased      = "evidence.legal_hold_released"
	EvidencePackCreated            = "evidence.pack_created"
	EvidencePackDownloaded         = "evidence.pack_downloaded"
	EvidencePayloadRead            = "evidence.payload_read"
	EvidenceRetentionChanged       = "evidence.retention_changed"
	EvidenceRetentionRemoved       = "evidence.retention_removed"
)

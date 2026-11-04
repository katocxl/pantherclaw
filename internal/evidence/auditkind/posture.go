// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "posture.". The ledger stores each as "audit." + the kind.
const (
	PostureFindingAccepted = "posture.finding_accepted"
	PostureFindingAssigned = "posture.finding_assigned"
	PostureFindingEvidenceIncomplete = "posture.finding_evidence_incomplete"
	PostureFindingNote = "posture.finding_note"
	PostureFindingReopened = "posture.finding_reopened"
	PostureFindingTesting = "posture.finding_testing"
)

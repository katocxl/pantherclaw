// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "approval.". The ledger stores each as "audit." + the kind.
const (
	ApprovalApproved = "approval.approved"
	ApprovalBatchApproved = "approval.batch_approved"
	ApprovalBatchDeclined = "approval.batch_declined"
	ApprovalConsumed = "approval.consumed"
	ApprovalDeclined = "approval.declined"
	ApprovalEvidenceRequested = "approval.evidence_requested"
	ApprovalEvidenceSubmitted = "approval.evidence_submitted"
	ApprovalExpired = "approval.expired"
	ApprovalGateConsumed = "approval.gate_consumed"
	ApprovalGateEnded = "approval.gate_ended"
	ApprovalGateRequested = "approval.gate_requested"
	ApprovalInvalidated = "approval.invalidated"
	ApprovalMultiPersonCompleted = "approval.multi_person_completed"
	ApprovalNarrowerProposed = "approval.narrower_proposed"
	ApprovalRequested = "approval.requested"
	ApprovalResponse = "approval.response"
	ApprovalResponseRefused = "approval.response_refused"
	ApprovalResponseVoided = "approval.response_voided"
	ApprovalRestorationCompleted = "approval.restoration_completed"
	ApprovalRestorationRequested = "approval.restoration_requested"
	ApprovalRestored = "approval.restored"
	ApprovalSuperseded = "approval.superseded"
)

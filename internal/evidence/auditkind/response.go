// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "response.". The ledger stores each as "audit." + the kind.
const (
	ResponseContain                 = "response.contain"
	ResponseCredentialRevoked       = "response.credential_revoked"
	ResponseCredentialRotated       = "response.credential_rotated"
	ResponseRestorationProposed     = "response.restoration_proposed"
	ResponseRestorationRequested    = "response.restoration_requested"
	ResponseRestorationStageApplied = "response.restoration_stage_applied"
	ResponseRestorationStageFailed  = "response.restoration_stage_failed"
	ResponseRunTerminated           = "response.run_terminated"
	ResponseSoarRateLimited         = "response.soar_rate_limited"
)

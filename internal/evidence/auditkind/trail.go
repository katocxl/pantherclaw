// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds of the Trail crypto (G0 M35 D1040, D1041), kept in one file:
// the deployment-wide root log, its witnesses, and the TUF refresh of
// Sigstore's trust material. Platform audit only. The ledger stores each as
// "audit." + the kind.
const (
	EvidenceGlobalLogFailed        = "evidence.global_log_failed"
	EvidenceTUFRefreshFailed       = "evidence.tuf_refresh_failed"
	EvidenceWitnessFailed          = "evidence.witness_failed"
	EvidenceWitnessThresholdNotMet = "evidence.witness_threshold_not_met"
)

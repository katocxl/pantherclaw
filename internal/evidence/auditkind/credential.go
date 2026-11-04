// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "credential.". The ledger stores each as "audit." + the kind.
//
//nolint:gosec // G101: audit kind names, not credentials
const (
	CredentialRevokeFailed             = "credential.revoke_failed"
	CredentialRotationActivated        = "credential.rotation_activated"
	CredentialRotationCandidateSealed  = "credential.rotation_candidate_sealed"
	CredentialRotationConfirmRequested = "credential.rotation_confirm_requested"
	CredentialRotationConfirmed        = "credential.rotation_confirmed"
	CredentialRotationFailed           = "credential.rotation_failed"
	CredentialRotationNotConfirmed     = "credential.rotation_not_confirmed"
	CredentialRotationRequested        = "credential.rotation_requested"
	CredentialRotationRolledBack       = "credential.rotation_rolled_back"
	CredentialRotationTestRequested    = "credential.rotation_test_requested"
	CredentialRotationTested           = "credential.rotation_tested"
	CredentialRotationWindowClosed     = "credential.rotation_window_closed"
)

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "support.". The ledger stores each as "audit." + the kind.
const (
	SupportAccessApproved      = "support.access_approved"
	SupportAccessDenied        = "support.access_denied"
	SupportAccessRequested     = "support.access_requested"
	SupportCall                = "support.call"
	SupportGrantRevoked        = "support.grant_revoked"
	SupportSelfDecisionRefused = "support.self_decision_refused"
	SupportSessionEnded        = "support.session_ended"
	SupportSessionOpened       = "support.session_opened"
)

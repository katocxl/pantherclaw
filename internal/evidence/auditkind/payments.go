// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds of agent payment verification (G0 M39 D1120, D1121, D1123;
// HR-830..832, HR-838): trust anchors created PENDING, activated with a
// security key and revoked; agent request signatures checked for merchant
// backends; and anything outside the sandbox refused. The ledger stores
// each as "audit." + the kind.
const (
	PaymentsAgentSignatureChecked = "payments.agent_signature_checked"
	PaymentsAnchorActivated       = "payments.anchor_activated"
	PaymentsAnchorCreated         = "payments.anchor_created"
	PaymentsAnchorRevoked         = "payments.anchor_revoked"
	SecurityPaymentsLiveRefused   = "security.payments_live_refused"
)

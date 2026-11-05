// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds of agent payment actions (G0 M39 D1124, D1124a..D1124d;
// HR-834..837, HR-840): a mandate the server verified or refused, a
// settled payment's effect (digests and verified facts only), a
// connection's merchant audience set, and merchant caps proposed (DRAFT,
// with their PAYMENT_CAP change request), activated by two people's
// confirmations and retired. The ledger stores each as "audit." + the kind.
const (
	PaymentsAudienceSet     = "payments.audience_set"
	PaymentsCapActivated    = "payments.cap_activated"
	PaymentsCapProposed     = "payments.cap_proposed"
	PaymentsCapRetired      = "payments.cap_retired"
	PaymentsEffect          = "payments.effect"
	PaymentsMandateRefused  = "payments.mandate_refused"
	PaymentsMandateVerified = "payments.mandate_verified"
)

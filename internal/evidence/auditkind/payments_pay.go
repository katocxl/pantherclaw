// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds of agent payment actions (G0 M39 D1124, D1124a; HR-834..837,
// HR-840): a mandate the payment step verified or refused, and merchant
// caps proposed (DRAFT, with their PAYMENT_CAP change request), activated
// by two people's confirmations, voided because one person alone could
// confirm them, and retired. The ledger stores each as "audit." + the kind.
const (
	PaymentsCapActivated    = "payments.cap_activated"
	PaymentsCapProposed     = "payments.cap_proposed"
	PaymentsCapRetired      = "payments.cap_retired"
	PaymentsCapVoided       = "payments.cap_voided"
	PaymentsMandateRefused  = "payments.mandate_refused"
	PaymentsMandateVerified = "payments.mandate_verified"
)

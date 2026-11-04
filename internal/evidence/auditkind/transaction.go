// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "transaction.". The ledger stores each as "audit." + the kind.
const (
	TransactionConsequenceNotVerifiable = "transaction.consequence_not_verifiable"
	TransactionConsequenceNotVerified   = "transaction.consequence_not_verified"
	TransactionConsequenceOpened        = "transaction.consequence_opened"
	TransactionLinked                   = "transaction.linked"
	TransactionReconciliationReleased   = "transaction.reconciliation_released"
	TransactionReconciliationResolved   = "transaction.reconciliation_resolved"
	TransactionVerificationRequested    = "transaction.verification_requested"
)

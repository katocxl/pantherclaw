// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "change.". The ledger stores each as "audit." + the kind.
const (
	ChangeApproved  = "change.approved"
	ChangeConfirmed = "change.confirmed"
	ChangeDeclined  = "change.declined"
	ChangeExpired   = "change.expired"
	ChangeRequested = "change.requested"
	ChangeVoided    = "change.voided"
)

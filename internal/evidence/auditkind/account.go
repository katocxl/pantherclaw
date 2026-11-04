// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "account.". The ledger stores each as "audit." + the kind.
const (
	AccountDeleted = "account.deleted"
	AccountDeletionStarted = "account.deletion_started"
	AccountUserDeleted = "account.user_deleted"
)

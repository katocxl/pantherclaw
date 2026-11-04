// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "org.". The ledger stores each as "audit." + the kind.
const (
	OrgDeleted         = "org.deleted"
	OrgDeletionStarted = "org.deletion_started"
	// The owned account list (G0 M30 D933).
	OrgOwnedAccountAdded   = "org.owned_account_added"
	OrgOwnedAccountRemoved = "org.owned_account_removed"
)

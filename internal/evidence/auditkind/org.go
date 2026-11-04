// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "org.". The ledger stores each as "audit." + the kind.
const (
	OrgDeleted = "org.deleted"
	OrgDeletionStarted = "org.deletion_started"
)

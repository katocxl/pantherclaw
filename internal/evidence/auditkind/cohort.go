// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "cohort.". The ledger stores each as "audit." + the kind.
const (
	CohortCreated        = "cohort.created"
	CohortDeleted        = "cohort.deleted"
	CohortMembersAdded   = "cohort.members_added"
	CohortMembersRemoved = "cohort.members_removed"
	CohortUpdated        = "cohort.updated"
)

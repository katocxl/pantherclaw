// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "coverage.". The ledger stores each as "audit." + the kind.
const (
	CoverageExclusionCreated = "coverage.exclusion_created"
	CoverageExclusionRevoked = "coverage.exclusion_revoked"
	CoverageFindingDismissed = "coverage.finding_dismissed"
	CoverageFindingResolved  = "coverage.finding_resolved"
)

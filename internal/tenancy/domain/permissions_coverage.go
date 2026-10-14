// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// Coverage permissions (G0 M9 track A). coverage.read covers coverage
// records, snapshots, the route inventory, closure evidence, exclusions and
// findings, scoped like agent.read over the agent. coverage.manage creates
// and revokes exclusions and acknowledges findings: both weaken what a
// claim says, so it is human only (HR-212). coverage.reassess recomputes
// coverage from evidence now, which can only make it more current.
const (
	PermCoverageRead     Permission = "coverage.read"
	PermCoverageManage   Permission = "coverage.manage"
	PermCoverageReassess Permission = "coverage.reassess"
)

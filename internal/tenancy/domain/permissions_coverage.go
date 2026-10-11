// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// Coverage permissions (G0 M9 track A). coverage.read covers coverage
// records, the route inventory, closure evidence, exclusions and findings,
// scoped like agent.read over the agent. coverage.manage reassesses
// coverage and dismisses findings; coverage.exclude creates and revokes
// exclusions, a weakening change (HR-212). Both are human only.
const (
	PermCoverageRead    Permission = "coverage.read"
	PermCoverageManage  Permission = "coverage.manage"
	PermCoverageExclude Permission = "coverage.exclude"
)

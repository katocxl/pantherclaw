// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// Red-team range permissions (G0 M12, HR-224). redteam.run starts a range
// for a range agent in scope and records its results; it is not human only,
// because CI service accounts run the regression gate. redteam.read reads
// ranges and their results, scoped like agent.read over the range agent.
// Exporting an assurance report is evidence.export.
const (
	PermRedteamRun  Permission = "redteam.run"
	PermRedteamRead Permission = "redteam.read"
)

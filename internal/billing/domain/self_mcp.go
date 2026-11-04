// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// SelfMCP reports whether an Investigator may read through PantherClaw's own
// MCP server (G0 M27 D510): Team and above. Without it the role's five reads
// answer EDITION_REQUIRED.
func (e Entitlements) SelfMCP() bool { return e.Edition.Paid() }

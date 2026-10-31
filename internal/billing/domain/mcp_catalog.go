// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// MCPCatalog reports whether the org may keep an approved MCP server
// catalogue (G0 M24 D222): Team and above. Without it the catalogue reads as
// EDITION_REQUIRED; a revoke stays available, because it only stops things.
func (e Entitlements) MCPCatalog() bool { return e.Edition.Paid() }

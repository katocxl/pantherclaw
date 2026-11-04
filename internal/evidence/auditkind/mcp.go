// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "mcp.". The ledger stores each as "audit." + the kind.
const (
	McpCatalogModeChanged    = "mcp.catalog.mode_changed"
	McpCatalogServerApproved = "mcp.catalog.server_approved"
	McpCatalogServerDenied   = "mcp.catalog.server_denied"
	McpCatalogServerProposed = "mcp.catalog.server_proposed"
	McpCatalogServerRevoked  = "mcp.catalog.server_revoked"
)

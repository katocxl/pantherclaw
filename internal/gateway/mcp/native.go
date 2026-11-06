// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import "github.com/katocxl/pantherclaw/internal/definitions/domain"

// native reports whether the gateway serves a definition itself on a
// connection with no upstream MCP server: a postgres connection's reviewed
// reads (G0 M14 D17) and a vectorstore connection's queries and writes
// (G0 M30 D922), and a snowflake connection's reviewed reads (G0 M31
// D962), whose tools the face lists and calls like any other.
func native(kind string, d *domain.Definition) bool {
	return (kind == "postgres" || kind == "vectorstore" || kind == "snowflake") && d.Dispatch != nil && d.Dispatch.SQL != nil
}

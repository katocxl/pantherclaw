// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// IdpAccess reports whether the organization may add assertion issuers,
// client bindings and MCP clients, or turn MCP authorization on (G0 M26,
// Editions: every paid edition). It gates filing and applying such a change
// only, never the token path (HR-357): what is ACTIVE keeps working after a
// downgrade, and turning something off works in every edition.
func (e Entitlements) IdpAccess() bool { return e.Edition.Paid() }

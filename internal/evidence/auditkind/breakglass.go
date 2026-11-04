// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "breakglass.". The ledger stores each as "audit." + the kind.
const (
	BreakglassActivated = "breakglass.activated"
	BreakglassCall = "breakglass.call"
	BreakglassEnded = "breakglass.ended"
	BreakglassHoldersChanged = "breakglass.holders_changed"
)

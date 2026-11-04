// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "platform.". The ledger stores each as "audit." + the kind.
const (
	PlatformMaintenanceHoldOff = "platform.maintenance_hold_off"
	PlatformMaintenanceHoldOn = "platform.maintenance_hold_on"
)

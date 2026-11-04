// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "threatmap.". The ledger stores each as "audit." + the kind.
const (
	// ThreatmapLaneLost is a lane that dropped since the newest stored
	// snapshot day; pc.threatmap.lane_lost reads it (G0 M28 D719).
	ThreatmapLaneLost = "threatmap.lane_lost"
)

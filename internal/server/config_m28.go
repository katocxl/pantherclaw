// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"fmt"

	"github.com/katocxl/pantherclaw/internal/platform/config"
	tmapp "github.com/katocxl/pantherclaw/internal/threatmap/app"
)

// ThreatMapConfig configures the threat map's daily snapshot (G0 M28 D719).
type ThreatMapConfig struct {
	// SnapshotInterval is how often the snapshot dispatcher runs: an hour
	// when unset, at least 10 seconds. A day keeps its newest run.
	SnapshotInterval config.Duration `json:"snapshot_interval" env:"PC_THREAT_MAP_SNAPSHOT_INTERVAL"`
}

func (c *Config) validateThreatMap() []error {
	if d := c.ThreatMap.SnapshotInterval.D(); d != 0 && d < tmapp.MinSnapshotInterval {
		return []error{fmt.Errorf("threat_map.snapshot_interval must be at least %s", tmapp.MinSnapshotInterval)}
	}
	return nil
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	tmapp "github.com/katocxl/pantherclaw/internal/threatmap/app"
)

// TestM28_ServeRegistersTheSnapshotJobs: the wiring runServe calls registers
// both threat map snapshot job kinds and adds one periodic dispatcher, at
// the shortest interval too (G0 M28 D719, D727a).
// Covers: F972, HR-687
func TestM28_ServeRegistersTheSnapshotJobs(t *testing.T) {
	for _, interval := range []time.Duration{0, tmapp.MinSnapshotInterval} {
		reg := jobs.NewRegistry()
		periodic, err := registerM28ThreatMapJobs(nil, reg, &db.Pool{}, nil,
			ThreatMapConfig{SnapshotInterval: config.Duration(interval)}, nil)
		if err != nil || len(periodic) != 1 {
			t.Fatalf("interval %s: %d periodic jobs, %v", interval, len(periodic), err)
		}
		if k := reg.Kinds(); !slices.Contains(k, "threatmap.snapshot") || !slices.Contains(k, "threatmap.snapshot_org") {
			t.Errorf("interval %s: kinds %v", interval, k)
		}
	}
}

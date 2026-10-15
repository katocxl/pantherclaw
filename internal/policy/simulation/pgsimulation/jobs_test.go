// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgsimulation_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/policy/simulation"
	"github.com/katocxl/pantherclaw/internal/policy/simulation/pgsimulation"
)

// TestSimulationJobRegisters: the job's arguments carry ids only (HR-056),
// so the worker registers.
func TestSimulationJobRegisters(t *testing.T) {
	if err := pgsimulation.Register(jobs.NewRegistry(), &simulation.Runner{}, nil); err != nil {
		t.Fatal(err)
	}
}

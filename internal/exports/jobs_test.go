// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package exports

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// The server refuses to start on a job whose args break HR-056, so every
// worker here must register.
func TestHR056_ExportJobsRegister(t *testing.T) {
	reg := jobs.NewRegistry()
	periodic, err := Register(reg, &Service{})
	if err != nil {
		t.Fatal(err)
	}
	if len(periodic) != 1 {
		t.Errorf("periodic jobs = %d, want the sweep", len(periodic))
	}
	if got := len(reg.Kinds()); got != 3 {
		t.Errorf("kinds = %v, want three", reg.Kinds())
	}
}

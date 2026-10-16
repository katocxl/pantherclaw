// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgengine

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// The driver's jobs register: their arguments carry typed ids only
// (HR-056), so a worker process starts.
func TestHR056_EngineJobsRegister(t *testing.T) {
	if _, err := Register(jobs.NewRegistry(), &Engine{}); err != nil {
		t.Fatal(err)
	}
	id := ids.NewV7()
	args, err := executionArgs(ids.New[ids.Org](), id)
	if err != nil || args.Execution.UUID() != id {
		t.Fatalf("execution args %+v, %v", args, err)
	}
}

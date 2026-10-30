// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"reflect"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// TestGenerateArgsCarryIDsOnly: the generation job's arguments pass the
// job-argument check (HR-056), so the worker registers.
//
// Covers: F185
func TestGenerateArgsCarryIDsOnly(t *testing.T) {
	if err := jobs.CheckArgs(reflect.TypeFor[GenerateArgs]()); err != nil {
		t.Fatal(err)
	}
}

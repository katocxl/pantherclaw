// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package globallog

import (
	"strings"
	"testing"
)

// TestHR782_TheWitnessedOriginIsTheGlobalLog: witnesses are given the
// deployment log plus /global, never a per-org origin.
func TestHR782_TheWitnessedOriginIsTheGlobalLog(t *testing.T) {
	got := Origin("logs.example")
	if got != "logs.example/global" || strings.Contains(got, "/org/") {
		t.Fatalf("origin %s", got)
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package docker

import (
	"runtime"
	"testing"
)

// TestHR228_TheModeIsChosenByEngine: Docker Desktop's containers keep
// host.docker.internal; a native engine on Linux reaches the host through
// the per-session relay, and no other host does.
func TestHR228_TheModeIsChosenByEngine(t *testing.T) {
	if (Engine{Desktop: true}).UsesRelay() {
		t.Error("Docker Desktop uses the relay")
	}
	if got, want := (Engine{}).UsesRelay(), runtime.GOOS == "linux"; got != want {
		t.Errorf("a native engine on %s: relay %v, want %v", runtime.GOOS, got, want)
	}
}

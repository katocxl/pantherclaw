// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHR396_FIPSNodeNeverFallsBackToOrdinaryImages(t *testing.T) {
	previous := nodeFIPSEnabled
	nodeFIPSEnabled = func() bool { return true }
	t.Cleanup(func() { nodeFIPSEnabled = previous })
	dir := filepath.Join(t.TempDir(), "node")
	err := nodeUp(context.Background(), &app{stderr: io.Discard, stdout: io.Discard}, []string{"--dir", dir})
	if err == nil || !strings.Contains(err.Error(), "FIPS container images") {
		t.Fatalf("FIPS fallback was not refused: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("FIPS refusal must precede node files or Docker execution")
	}
}

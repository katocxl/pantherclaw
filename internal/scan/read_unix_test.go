// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build unix

package scan_test

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/scan"
)

// TestD254_AFIFODoesNotHangTheScan: a FIFO in a home is refused at once, with
// nobody at its other end.
// Covers: F883
func TestD254_AFIFODoesNotHangTheScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan []byte, 1)
	go func() { done <- scan.ReadFile(path) }()
	select {
	case got := <-done:
		if got != nil {
			t.Fatalf("read %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the scan waits on a FIFO")
	}
}

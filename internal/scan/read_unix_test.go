// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build unix

package scan_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/scan"
)

// dirLink makes link point at the directory target.
func dirLink(link, target string) error { return os.Symlink(target, link) }

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

// TestD282_AContainedReadFollowsNoLink: a link put in place after the Lstat is
// refused at the open.
// Covers: F886
func TestD282_AContainedReadFollowsNoLink(t *testing.T) {
	dir := t.TempDir()
	path, secret := filepath.Join(dir, "settings.json"), filepath.Join(dir, "secret")
	for _, p := range []string{path, secret} {
		if err := os.WriteFile(p, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	defer scan.SetAfterLstat(func() {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(secret, path); err != nil {
			t.Error(err)
		}
	})()
	if got := scan.ReadContained(dir, path); got != nil {
		t.Fatalf("followed a link: %q", got)
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scan_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/katocxl/pantherclaw/internal/scan"
)

// TestD254_WhatIsReadIsWhatWasChecked: a file that grows past the limit after
// its check is not read, so the size limit holds on the bytes themselves.
// Covers: F883
func TestD254_WhatIsReadIsWhatWasChecked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	defer scan.SetAfterCheck(func() {
		if err := os.WriteFile(path, bytes.Repeat([]byte(" "), scan.MaxFileSize+1), 0o600); err != nil {
			t.Error(err)
		}
	})()
	if got := scan.ReadFile(path); got != nil {
		t.Fatalf("read %d bytes past the limit", len(got))
	}
}

// TestD254_ADirectoryIsNotRead: only a regular file passes the open file's
// check.
// Covers: F883
func TestD254_ADirectoryIsNotRead(t *testing.T) {
	if got := scan.ReadFile(t.TempDir()); got != nil {
		t.Fatalf("read %q", got)
	}
}

// TestD282_AContainedReadRefusesASwappedFile: a file replaced after it was
// looked at is not read, in another person's home.
// Covers: F886
func TestD282_AContainedReadRefusesASwappedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := scan.ReadContained(path); string(got) != `{}` {
		t.Fatalf("an untouched file: %q", got)
	}
	defer scan.SetAfterLstat(func() {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		if err := os.WriteFile(path, []byte(`{"swapped":1}`), 0o600); err != nil {
			t.Error(err)
		}
	})()
	if got := scan.ReadContained(path); got != nil {
		t.Fatalf("read the swapped file: %q", got)
	}
}

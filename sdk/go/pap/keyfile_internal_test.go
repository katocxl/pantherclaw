// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package pap

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteKeyFileWithoutHardLinks: on a filesystem without hard links a
// new key file is still written, and an existing one is still never
// replaced.
func TestWriteKeyFileWithoutHardLinks(t *testing.T) {
	saved := link
	link = func(string, string) error { return &os.LinkError{Op: "link", Err: errors.New("not supported")} }
	t.Cleanup(func() { link = saved })
	k, err := NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.key.json")
	if err := WriteKeyFile(path, k, false); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadKeyFile(path); err != nil || got != k {
		t.Fatalf("read back %v, %v", got, err)
	}
	other, _ := NewKeyFile()
	if err := WriteKeyFile(path, other, false); err == nil {
		t.Fatal("an existing key file was replaced")
	}
	if got, _ := ReadKeyFile(path); got != k {
		t.Fatal("the refused write changed the key")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("left behind %v", entries)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package pap_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/sdk/go/pap"
)

func newKeyFile(t *testing.T) pap.KeyFile {
	t.Helper()
	k, err := pap.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	k.Identifier, k.Server = "pc:org/o/agent/a/inst/i", "https://pantherclaw.example.test"
	return k
}

// TestKeyFileNeverPrintsItsSeed: printing or logging a key file shows its
// identity, never its private key.
func TestKeyFileNeverPrintsItsSeed(t *testing.T) {
	k := newKeyFile(t)
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("enrolled", "key", k)
	for _, out := range []string{fmt.Sprintf("%v %+v %#v %s", k, k, k, k), fmt.Sprint(&k), logged.String()} {
		if strings.Contains(out, k.PrivateKey) || !strings.Contains(out, k.Identifier) {
			t.Errorf("printed %q", out)
		}
	}
}

// TestWriteKeyFileReplacesAtomically: a replacement leaves exactly the new
// key, owner-only whatever the old file's mode, and no temporary file; a
// write that may not replace leaves the old key.
func TestWriteKeyFileReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.key.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	k := newKeyFile(t)
	if err := pap.WriteKeyFile(path, k, false); err == nil {
		t.Fatal("an existing file was replaced without replace")
	}
	if b, _ := os.ReadFile(path); string(b) != "old" {
		t.Fatalf("the refused write changed the file: %q", b)
	}
	if err := pap.WriteKeyFile(path, k, true); err != nil {
		t.Fatal(err)
	}
	got, err := pap.ReadKeyFile(path)
	if err != nil || got != k {
		t.Fatalf("read back %v, %v", got, err)
	}
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", info.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("left behind %v", entries)
	}
}

// TestReadKeyFileRefusesAFileOthersCanRead: outside Windows, a key file
// open to the group or others is refused, as ssh refuses such a key.
func TestReadKeyFileRefusesAFileOthersCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows keeps access in the file's access list, not its mode")
	}
	path := filepath.Join(t.TempDir(), "agent.key.json")
	if err := pap.WriteKeyFile(path, newKeyFile(t), false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := pap.ReadKeyFile(path); err == nil {
		t.Fatal("read a key file the group can read")
	}
}

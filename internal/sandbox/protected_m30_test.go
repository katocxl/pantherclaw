// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
)

// TestHR713_ProtectedFilesAreBoundReadOnly: each existing agent
// configuration or memory file of the workspace is copied into the
// session's directory and bound read-only over /workspace/<path>; ordinary
// files and anything under .git get no bind, and a workspace with no such
// file gets none (G0 M30 D944).
func TestHR713_ProtectedFilesAreBoundReadOnly(t *testing.T) {
	ws, dir := t.TempDir(), t.TempDir()
	for rel, content := range map[string]string{
		"CLAUDE.md": "memory", ".claude/settings.json": "{}", "main.go": "package main",
		".git/CLAUDE.md": "not the workspace's", "docs/CLAUDE.md": "not listed",
	} {
		p := filepath.Join(ws, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := &Sandbox{o: Options{Dir: dir}}
	mounts, err := s.protectedBinds(ws)
	if err != nil {
		t.Fatal(err)
	}
	var targets []string
	for _, m := range mounts {
		targets = append(targets, m.Target)
		if m.Kind != docker.Bind || !m.ReadOnly || !strings.HasPrefix(m.Source, filepath.Join(dir, "protected")) {
			t.Errorf("mount %+v", m)
		}
		if b, err := os.ReadFile(m.Source); err != nil || len(b) == 0 {
			t.Errorf("copy %s: %q %v", m.Source, b, err)
		}
	}
	slices.Sort(targets)
	if !slices.Equal(targets, []string{"/workspace/.claude/settings.json", "/workspace/CLAUDE.md"}) {
		t.Fatalf("targets %v", targets)
	}

	plain := t.TempDir()
	if err := os.WriteFile(filepath.Join(plain, "main.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}
	if mounts, err := (&Sandbox{o: Options{Dir: t.TempDir()}}).protectedBinds(plain); err != nil || len(mounts) != 0 {
		t.Fatalf("a workspace without protected files: %v %v", mounts, err)
	}
}

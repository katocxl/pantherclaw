// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scan_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
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

// TestD287_AContainedScanFollowsNoLinkToTheRegistry: the JetBrains registry
// moves an mcp.json, so a link at it, or above it, would have root read a file
// its owner chose. A contained scan reads the real file and refuses the links.
// Covers: F886
func TestD287_AContainedScanFollowsNoLinkToTheRegistry(t *testing.T) {
	const registry = `<application><component name="Registry">` +
		`<entry key="llm.mcp.client.global.mcp.json.path" value="moved/mcp.json" source="USER" /></component></application>`
	scanned := func(t *testing.T, plant func(options, outside string) error) []string {
		t.Helper()
		root := t.TempDir()
		home, outside := filepath.Join(root, "home"), filepath.Join(root, "outside")
		options := filepath.Join(home, ".config", "JetBrains", "IDEA2026.2", "options")
		write(t, filepath.Join(home, "moved", "mcp.json"), `{"mcpServers": {"moved": {"command": "npx"}}}`)
		write(t, filepath.Join(outside, "ide.general.xml"), registry)
		if err := os.MkdirAll(options, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := plant(options, outside); err != nil {
			t.Skipf("no symbolic links here: %v", err)
		}
		var names []string
		for _, f := range scan.Run(scan.Options{Home: home, ConfigDir: filepath.Join(home, ".config"), Contained: true}) {
			names = append(names, f.Attributes["name"])
		}
		return names
	}
	plain := scanned(t, func(options, _ string) error {
		return os.WriteFile(filepath.Join(options, "ide.general.xml"), []byte(registry), 0o600)
	})
	if !slices.Contains(plain, "moved") {
		t.Fatalf("the real registry moved nothing: %v", plain)
	}
	for name, plant := range map[string]func(options, outside string) error{
		"a link at the file": func(options, outside string) error {
			return os.Symlink(filepath.Join(outside, "ide.general.xml"), filepath.Join(options, "ide.general.xml"))
		},
		"a link at its directory": func(options, outside string) error {
			if err := os.Remove(options); err != nil {
				return err
			}
			return dirLink(options, outside)
		},
		"a link at JetBrains": func(options, outside string) error {
			ide := filepath.Dir(options)
			write(t, filepath.Join(outside, "IDEA2026.2", "options", "ide.general.xml"), registry)
			if err := os.RemoveAll(filepath.Dir(ide)); err != nil {
				return err
			}
			return dirLink(filepath.Dir(ide), outside)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := scanned(t, plant); slices.Contains(got, "moved") {
				t.Fatalf("followed a link: %v", got)
			}
		})
	}
}

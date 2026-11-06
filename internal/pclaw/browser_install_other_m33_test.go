// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package pclaw

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestHR753_TheManifestGoesWhereChromeReadsIt: for the user, the manifest
// is written into each chosen browser's NativeMessagingHosts directory
// under the home directory, and only those.
func TestHR753_TheManifestGoesWhereChromeReadsIt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	written, err := registerBrowserHost("", []string{"chromium"}, false, []byte(`{}`))
	if err != nil || len(written) != 1 {
		t.Fatalf("register = %v, %v", written, err)
	}
	want := filepath.Join(home, ".config", "chromium", "NativeMessagingHosts", browserHostName+".json")
	if runtime.GOOS == "darwin" {
		want = filepath.Join(home, "Library", "Application Support", "Chromium", "NativeMessagingHosts", browserHostName+".json")
	}
	if written[0] != want {
		t.Fatalf("wrote %s, want %s", written[0], want)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(filepath.Dir(want)), "..", "google-chrome")); err == nil {
		t.Error("registered for a browser that was not chosen")
	}
	dirs, _ := browserHostDirs(true)
	if dirs["chrome"] == "" || dirs["chromium"] == "" || filepath.Dir(dirs["chrome"]) == home {
		t.Errorf("system dirs %v", dirs)
	}
}

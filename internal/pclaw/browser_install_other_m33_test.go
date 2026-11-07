// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package pclaw

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// TestHR753_SystemInstallNeedsRootAndARootOnlyFolder: --system without
// root is refused before anything is written, and a system folder someone
// other than root owns or can write is refused; a file the person owns is
// not root-owned.
func TestHR753_SystemInstallNeedsRootAndARootOnlyFolder(t *testing.T) {
	fi, err := os.Stat(hostConfigFile(t, 0o644))
	if err != nil {
		t.Fatal(err)
	}
	if browserFileOwnedByRoot(fi) != (os.Geteuid() == 0) {
		t.Errorf("owned by root = %v as uid %d", browserFileOwnedByRoot(fi), os.Geteuid())
	}
	dir := filepath.Join(t.TempDir(), "PantherClaw", "browser")
	err = prepareBrowserInstallDir(dir, true)
	if os.Geteuid() != 0 {
		if err == nil || !strings.Contains(err.Error(), "needs root") {
			t.Fatalf("--system as uid %d: %v", os.Geteuid(), err)
		}
		if _, err := os.Stat(dir); err == nil {
			t.Error("made the folder before refusing")
		}
		r := recordInstall(t)
		keyFile, _, _ := proxyFiles(t)
		if code, _, _ := runArgs(t, "browser", "install-host", "--gateway", "https://gw.example.test", "--connection", "browser",
			"--key-file", keyFile, "--extension-id", extOK, "--system"); code == 0 || r.manifest != nil {
			t.Errorf("--system as uid %d = %d, registered %s", os.Geteuid(), code, r.manifest)
		}
		return
	}
	if err != nil {
		t.Fatalf("as root: %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := prepareBrowserInstallDir(dir, true); err == nil {
		t.Error("a folder others can write was accepted")
	}
}

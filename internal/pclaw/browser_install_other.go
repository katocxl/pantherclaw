// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package pclaw

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

// browserHostDirs are the directories Chrome and Chromium read host
// manifests from (G0 M33 D979).
func browserHostDirs(system bool) (map[string]string, error) {
	if system {
		if runtime.GOOS == "darwin" {
			return map[string]string{
				"chrome":   "/Library/Google/Chrome/NativeMessagingHosts",
				"chromium": "/Library/Application Support/Chromium/NativeMessagingHosts",
			}, nil
		}
		return map[string]string{
			"chrome":   "/etc/opt/chrome/native-messaging-hosts",
			"chromium": "/etc/chromium/native-messaging-hosts",
		}, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	if runtime.GOOS == "darwin" {
		base := filepath.Join(home, "Library", "Application Support")
		return map[string]string{
			"chrome":   filepath.Join(base, "Google", "Chrome", "NativeMessagingHosts"),
			"chromium": filepath.Join(base, "Chromium", "NativeMessagingHosts"),
		}, nil
	}
	return map[string]string{
		"chrome":   filepath.Join(home, ".config", "google-chrome", "NativeMessagingHosts"),
		"chromium": filepath.Join(home, ".config", "chromium", "NativeMessagingHosts"),
	}, nil
}

// prepareBrowserInstallDir makes the install folder. --system writes under
// /etc or /Library and the configuration must end up owned by root, so it
// needs root; a folder there that someone other than root owns or can
// write is refused.
func prepareBrowserInstallDir(dir string, system bool) error {
	if system && os.Geteuid() != 0 {
		return errors.New("--system needs root: run it with sudo")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: the manifest and wrapper must be readable by the browser
		return err
	}
	if !system {
		return nil
	}
	for _, d := range []string{filepath.Dir(dir), dir} {
		fi, err := os.Lstat(d)
		if err != nil {
			return err
		}
		if !fi.IsDir() || !browserFileOwnedByRoot(fi) || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is not a folder only root can change: remove it or chown root and chmod 755 it", d)
		}
	}
	return nil
}

// browserFileOwnedByRoot says whether root owns a file.
func browserFileOwnedByRoot(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

// registerBrowserHost writes the manifest into each browser's directory.
func registerBrowserHost(_ string, browsers []string, system bool, manifest []byte) ([]string, error) {
	dirs, err := browserHostDirs(system)
	if err != nil {
		return nil, err
	}
	var written []string
	for _, b := range browsers {
		if err := os.MkdirAll(dirs[b], 0o755); err != nil { //nolint:gosec // G301: the browser reads it
			return written, err
		}
		path := filepath.Join(dirs[b], browserHostName+".json")
		if err := writeFileMode(path, manifest, 0o644); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

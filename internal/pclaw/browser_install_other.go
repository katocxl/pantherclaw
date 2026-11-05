// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package pclaw

import (
	"os"
	"path/filepath"
	"runtime"
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

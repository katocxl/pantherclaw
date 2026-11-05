// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build windows

package pclaw

import (
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// browserHostKeys are the registry keys, under HKCU or HKLM, whose default
// value names the host manifest (G0 M33 D979).
var browserHostKeys = map[string]string{
	"chrome":   `Software\Google\Chrome\NativeMessagingHosts\` + browserHostName,
	"chromium": `Software\Chromium\NativeMessagingHosts\` + browserHostName,
}

// registerBrowserHost writes the manifest next to the configuration and
// registers it for each browser.
func registerBrowserHost(dir string, browsers []string, system bool, manifest []byte) ([]string, error) {
	path := filepath.Join(dir, browserHostName+".json")
	if err := writeFileMode(path, manifest, 0o644); err != nil {
		return nil, err
	}
	root, hive := registry.CURRENT_USER, `HKCU\`
	if system {
		root, hive = registry.LOCAL_MACHINE, `HKLM\`
	}
	written := []string{path}
	for _, b := range browsers {
		k, _, err := registry.CreateKey(root, browserHostKeys[b], registry.SET_VALUE)
		if err != nil {
			return written, err
		}
		err = k.SetStringValue("", path)
		_ = k.Close()
		if err != nil {
			return written, err
		}
		written = append(written, hive+browserHostKeys[b])
	}
	return written, nil
}

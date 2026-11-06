// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build windows

package pclaw

import "testing"

// TestHR753_TheManifestIsRegisteredUnderChromesKeys: on Windows the
// manifest is named by the default value of Chrome's and Chromium's
// NativeMessagingHosts key for the host name (the test does not write the
// registry).
func TestHR753_TheManifestIsRegisteredUnderChromesKeys(t *testing.T) {
	want := map[string]string{
		"chrome":   `Software\Google\Chrome\NativeMessagingHosts\dev.pantherclaw.browser`,
		"chromium": `Software\Chromium\NativeMessagingHosts\dev.pantherclaw.browser`,
	}
	for b, k := range want {
		if browserHostKeys[b] != k {
			t.Errorf("%s key %q, want %q", b, browserHostKeys[b], k)
		}
	}
	if len(browserHostKeys) != len(want) {
		t.Errorf("keys %v", browserHostKeys)
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package servercli

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/extension"
)

// Main runs the same command line as before the extension point: usage
// errors exit 2, version exits 0, with or without an extension set.
func TestMain_ExitCodes(t *testing.T) {
	ext := extension.Set{Validate: func(extension.Deps) error { t.Error("Validate outside serve"); return nil }}
	for _, set := range []extension.Set{{}, ext} {
		if c := Main(nil, set); c != 2 {
			t.Errorf("no arguments = %d, want 2", c)
		}
		if c := Main([]string{"no-such-command"}, set); c != 2 {
			t.Errorf("unknown command = %d, want 2", c)
		}
		if c := Main([]string{"version"}, set); c != 0 {
			t.Errorf("version = %d, want 0", c)
		}
	}
}

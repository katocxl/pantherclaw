// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build windows

package pclaw

import (
	"os"
	"path/filepath"
)

// platformMachineDir is the machine-wide pclaw directory, or "".
func platformMachineDir() string {
	d := os.Getenv("ProgramData")
	if d == "" {
		return ""
	}
	return filepath.Join(d, "PantherClaw")
}

func platformBinaryProtected(exe string) bool {
	return windowsBinaryProtected(exe, os.Getenv("ProgramFiles"), os.Getenv("SystemRoot"))
}

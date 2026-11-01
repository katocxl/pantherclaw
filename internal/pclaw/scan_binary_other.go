// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package pclaw

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// platformMachineDir is the machine-wide pclaw directory.
func platformMachineDir() string { return "/var/lib/pantherclaw" }

func platformBinaryProtected(exe string) bool { return unixBinaryProtected(exe, ownerAndMode) }

func ownerAndMode(path string) (uint32, fs.FileMode, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("pclaw: no owner for " + path)
	}
	return st.Uid, info.Mode(), nil
}

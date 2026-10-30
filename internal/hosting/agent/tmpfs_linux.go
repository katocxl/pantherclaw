// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build linux

package agent

import (
	"os"

	"golang.org/x/sys/unix"
)

// tmpfsMagic is the tmpfs file system's statfs type.
const tmpfsMagic = 0x01021994

// checkTmpfs fails unless path is on a tmpfs.
func checkTmpfs(path string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return err
	}
	if st.Type != tmpfsMagic {
		return ErrNotTmpfs
	}
	return nil
}

// chownTo hands path to uid (as its own group too).
func chownTo(path string, uid int) error { return os.Lchown(path, uid, uid) }

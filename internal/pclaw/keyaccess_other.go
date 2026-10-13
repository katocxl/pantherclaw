// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package pclaw

import (
	"fmt"
	"os"
)

// keyFileReaders says who other than the person can read or change a key
// file ("" when no one can) and how the person stops them: on POSIX
// systems, its group and other permission bits.
func keyFileReaders(path string) (who, fix string, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", "", err
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Sprintf("mode %04o", mode), "run chmod 600 on it", nil
	}
	return "", "", nil
}

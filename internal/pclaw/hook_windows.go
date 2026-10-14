// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"errors"

	"golang.org/x/sys/windows"
)

// GetFinalPathNameByHandle flags: the normalized name (long names), with
// the volume as a drive letter or UNC share.
const (
	fileNameNormalized = 0x0
	volumeNameDOS      = 0x0
)

// resolveFinal asks Windows for the final path of an existing directory: it
// opens it, which follows symbolic links, junctions, mount points and
// substituted drives, and reads the name of what it opened.
// filepath.EvalSymlinks cannot be used: since Go 1.23 it no longer follows
// junctions, which any user can create (mklink /J).
func resolveFinal(abs string) (string, error) {
	name, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(name, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], windows.MAX_LONG_PATH, fileNameNormalized|volumeNameDOS)
	if err != nil {
		return "", err
	}
	if n == 0 || n >= windows.MAX_LONG_PATH {
		return "", errors.New("the final path is too long")
	}
	return dosPath(windows.UTF16ToString(buf[:n]))
}

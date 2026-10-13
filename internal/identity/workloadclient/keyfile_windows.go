// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build windows

package workloadclient

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// createPrivate creates a new file, never an existing one, with an access
// list of its own from the start: full control for the person, SYSTEM and
// Administrators, nothing for anyone else and nothing inherited from its
// folder. Windows ignores the 0600 mode, a home or temp folder often lets
// other accounts read what it holds, and a file made private only after it
// was created could be opened by one of them in between (HR-208).
func createPrivate(path string) (*os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	// P: protected, so nothing is inherited; FA: full access.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

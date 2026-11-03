// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build windows

package siemforward

import (
	"errors"
	"io/fs"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// openOutput opens path for reading and appending. An existing file keeps
// its access list. A missing one is created with an access list of its own
// from the start (the pattern of workloadclient's createPrivate): full
// control for the forwarder's user, SYSTEM and Administrators, nothing for
// anyone else and nothing inherited from its folder. Windows ignores the
// 0600 mode, and a folder's inherited entries often let every local user
// change what it holds.
func openOutput(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // G304: the output file the operator names
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return f, err
	}
	f, err = createPrivate(path)
	if errors.Is(err, windows.ERROR_FILE_EXISTS) { // created in between: open what is there
		return os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // G304: the output file the operator names
	}
	return f, err
}

// createPrivate creates a new file, never an existing one, with the
// protected owner-only access list. Readers (the SIEM agent) and writers
// may share it while it is open; it can't be renamed or deleted then.
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
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build windows

package pclaw

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// keyFileReaders says who other than the person can read or change a key
// file ("" when no one can) and how the person stops them. On Windows that
// is the file's owner and access list: besides the person, only SYSTEM and
// the Administrators group, which can read any file anyway, may own it or
// be allowed to read, write or execute it or change its permissions. An
// access entry pclaw cannot read counts against the file.
func keyFileReaders(path string) (who, fix string, err error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", "", err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", "", err
	}
	me := user.User.Sid
	fix = fmt.Sprintf(`remove every entry but yours (%s) from its permissions; icacls "%s" /inheritance:r /grant:r "%s:F" `+
		`removes the inherited ones and lists the rest`, account(me), path, account(me))
	trusted := func(sid *windows.SID) bool {
		return sid.Equals(me) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return "", "", err
	}
	if !trusted(owner) {
		return "it is owned by " + account(owner), fix, nil
	}
	dacl, _, err := sd.DACL()
	switch {
	case errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil):
		return "it has no access list, so everyone may", fix, nil
	case err != nil:
		return "", "", err
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return "", "", err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue // it applies only to what a directory holds
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, accessDeniedObjectACE, accessDeniedCallbackACE, accessDeniedCallbackObjectACE:
			continue // a denial only takes access away
		case windows.ACCESS_ALLOWED_ACE_TYPE, accessAllowedCallbackACE:
		default:
			return "its access list has an entry pclaw cannot check", fix, nil
		}
		// The entry's SID starts at SidStart, as in ACCESS_ALLOWED_ACE.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // G103: the layout Windows defines for these entries
		if !trusted(sid) && ace.Mask&readOrChange != 0 {
			return "its access list allows " + account(sid), fix, nil
		}
	}
	return "", "", nil
}

// Access entry types beyond the two x/sys/windows names
// (learn.microsoft.com, ACE_HEADER).
const (
	accessDeniedObjectACE         = 6
	accessAllowedCallbackACE      = 9
	accessDeniedCallbackACE       = 10
	accessDeniedCallbackObjectACE = 12
)

// readOrChange is the access that lets someone read, change or run a key
// file, or change who may.
const readOrChange = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_EXECUTE |
	windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_EXECUTE | windows.GENERIC_ALL

// account is a SID's account name (DOMAIN\name), or the SID itself.
func account(sid *windows.SID) string {
	name, domain, _, err := sid.LookupAccount("")
	switch {
	case err != nil:
		return sid.String()
	case domain != "":
		return domain + `\` + name
	}
	return name
}

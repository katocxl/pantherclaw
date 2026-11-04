// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build windows

package siemforward

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ownerOnly checks the file's access list is protected (nothing inherited)
// and allows only the current user, SYSTEM and Administrators.
func ownerOnly(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("the access list is not protected: it inherits from the folder")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("no access list: %v", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me, mine := user.User.Sid, false
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case ace.Header.AceFlags&windows.INHERITED_ACE != 0:
			t.Errorf("an inherited entry for %s", sid)
		case ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE:
			t.Errorf("an entry of type %d for %s", ace.Header.AceType, sid)
		case sid.Equals(me):
			mine = true
		case sid.IsWellKnown(windows.WinLocalSystemSid), sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
		default:
			t.Errorf("the access list allows %s", sid)
		}
	}
	if !mine {
		t.Error("the access list has no entry for the forwarder's user")
	}
}

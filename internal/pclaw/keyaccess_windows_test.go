// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build windows

package pclaw

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
)

// access is an access entry for a SID: mode GRANT_ACCESS or DENY_ACCESS.
func access(sid *windows.SID, mode windows.ACCESS_MODE, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask, AccessMode: mode, Inheritance: windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}
}

// setAccess gives a file exactly these access entries, inheriting none;
// no entries at all is no access list (everyone may do anything).
func setAccess(t *testing.T, path string, entries ...windows.EXPLICIT_ACCESS) {
	t.Helper()
	var acl *windows.ACL
	if len(entries) > 0 {
		var err error
		if acl, err = windows.ACLFromEntries(entries, nil); err != nil {
			t.Fatal(err)
		}
	}
	err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func wellKnown(t *testing.T, kind windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(kind)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// TestHR208_InitRefusesAKeyFileOthersCanReadOnWindows: on Windows a key
// file's owner and access list say who can read it. One that lets anyone
// but the person, SYSTEM and Administrators read, change or run it or
// change its permissions, or that has no access list, is refused before
// anything is done, with how to fix it, and keeps its access list; a
// denial counts for no one. Once only the person may, init enrolls it.
func TestHR208_InitRefusesAKeyFileOthersCanReadOnWindows(t *testing.T) {
	const agent = "0192aaaa-bbbb-7ccc-8ddd-000000000001"
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := user.User.Sid
	everyone, users := wellKnown(t, windows.WinWorldSid), wellKnown(t, windows.WinBuiltinUsersSid)
	system, admins := wellKnown(t, windows.WinLocalSystemSid), wellKnown(t, windows.WinBuiltinAdministratorsSid)
	f := newInitFixture(t)
	fake := &fakeEnrollment{}
	f.enrollmentServer(t, fake)
	kf, _, err := workloadclient.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	if err := workloadclient.WriteKeyFile(f.key, kf, false); err != nil {
		t.Fatal(err)
	}
	mine := access(me, windows.GRANT_ACCESS, windows.GENERIC_ALL)

	setAccess(t, f.key, mine, access(system, windows.GRANT_ACCESS, windows.GENERIC_ALL), access(admins, windows.GRANT_ACCESS, windows.GENERIC_ALL),
		access(everyone, windows.DENY_ACCESS, windows.FILE_EXECUTE))
	if who, _, err := keyFileReaders(f.key); who != "" || err != nil {
		t.Fatalf("only the person, SYSTEM and Administrators: %q %v", who, err)
	}
	for name, tc := range map[string]struct {
		entries []windows.EXPLICIT_ACCESS
		want    string
	}{
		"everyone reads":               {[]windows.EXPLICIT_ACCESS{mine, access(everyone, windows.GRANT_ACCESS, windows.GENERIC_READ)}, account(everyone)},
		"users write":                  {[]windows.EXPLICIT_ACCESS{mine, access(users, windows.GRANT_ACCESS, windows.FILE_WRITE_DATA)}, account(users)},
		"users change its permissions": {[]windows.EXPLICIT_ACCESS{mine, access(users, windows.GRANT_ACCESS, windows.WRITE_DAC)}, account(users)},
		"no access list":               {nil, "no access list"},
	} {
		setAccess(t, f.key, tc.entries...)
		who, fix, err := keyFileReaders(f.key)
		if err != nil || !strings.Contains(who, tc.want) || !strings.Contains(fix, `icacls "`+f.key+`"`) {
			t.Errorf("%s: %q %q %v", name, who, fix, err)
		}
	}

	setAccess(t, f.key, mine, access(everyone, windows.GRANT_ACCESS, windows.GENERIC_READ))
	code, out, errs := f.run(t, "--agent", agent)
	if _, err := os.Stat(f.local()); code == 0 || err == nil || fake.issued != nil || !strings.Contains(errs, "other users can read") ||
		!strings.Contains(errs, account(everyone)) || !strings.Contains(errs, "icacls") {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
	if who, _, _ := keyFileReaders(f.key); !strings.Contains(who, account(everyone)) {
		t.Fatalf("the access list changed: %q", who)
	}
	setAccess(t, f.key, mine)
	if code, out, errs := f.run(t, "--agent", agent); code != 0 || fake.admitted == nil {
		t.Fatalf("init with a key only the person may read: %d %s %s", code, out, errs)
	}
}

// onlyTheUserReads lets only the user read or change a key file: an access
// list with the user alone, inheriting nothing from the directory (which,
// on a developer's machine, may let other accounts in).
func onlyTheUserReads(t *testing.T, path string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	setAccess(t, path, access(user.User.Sid, windows.GRANT_ACCESS, windows.GENERIC_ALL))
}

// TestHR208_AKeyFilePclawWritesIsItsOwnOnWindows: a key file pclaw writes
// gets an access list of its own, so init accepts it even in a folder that
// lets everyone read what it holds, where any other new file is refused.
func TestHR208_AKeyFilePclawWritesIsItsOwnOnWindows(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	everyone := wellKnown(t, windows.WinWorldSid)
	dir := t.TempDir()
	inherited := func(e windows.EXPLICIT_ACCESS) windows.EXPLICIT_ACCESS {
		e.Inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
		return e
	}
	setAccess(t, dir, inherited(access(user.User.Sid, windows.GRANT_ACCESS, windows.GENERIC_ALL)),
		inherited(access(everyone, windows.GRANT_ACCESS, windows.GENERIC_READ)))

	other := dir + `\other.json`
	if err := os.WriteFile(other, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if who, _, err := keyFileReaders(other); err != nil || !strings.Contains(who, account(everyone)) {
		t.Fatalf("a file the folder lets everyone read: %q %v", who, err)
	}
	kf, _, err := workloadclient.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	for _, replace := range []bool{false, true} {
		key := dir + `\key.json`
		if replace {
			key = other
		}
		if err := workloadclient.WriteKeyFile(key, kf, replace); err != nil {
			t.Fatal(err)
		}
		if who, _, err := keyFileReaders(key); who != "" || err != nil {
			t.Fatalf("a key file pclaw wrote (replace %v): %q %v", replace, who, err)
		}
	}
}

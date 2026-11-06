// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build windows

package pclaw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// browserDirOwnedBy makes the owner check answer sid.
func browserDirOwnedBy(t *testing.T, sid windows.WELL_KNOWN_SID_TYPE) {
	t.Helper()
	s, err := windows.CreateWellKnownSid(sid)
	if err != nil {
		t.Fatal(err)
	}
	old := browserDirOwnerFn
	browserDirOwnerFn = func(string) (*windows.SID, error) { return s, nil }
	t.Cleanup(func() { browserDirOwnerFn = old })
}

// TestHR753_SystemInstallRefusesAFolderOthersOwn: install-host --system
// goes under %ProgramFiles%\PantherClaw\browser; an existing folder there
// not owned by SYSTEM or Administrators, or something there that is not a
// folder, is refused before anything is written or registered.
func TestHR753_SystemInstallRefusesAFolderOthersOwn(t *testing.T) {
	r := recordInstall(t)
	keyFile, _, _ := proxyFiles(t)
	pf := t.TempDir()
	dir := filepath.Join(pf, "PantherClaw", "browser")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	browserDirOwnedBy(t, windows.WinWorldSid)
	env := envOf(map[string]string{"ProgramFiles": pf})
	code, _, errs := run(t, env, "browser", "install-host", "--gateway", "https://gw.example.test", "--connection", "browser",
		"--key-file", keyFile, "--extension-id", extOK, "--system")
	if code == 0 || !strings.Contains(errs, "not SYSTEM or Administrators") || r.manifest != nil {
		t.Fatalf("install-host --system = %d %q, registered %s", code, errs, r.manifest)
	}
	if _, err := os.Stat(filepath.Join(dir, "host-config.json")); err == nil {
		t.Error("wrote the configuration")
	}
	if got, err := browserInstallDir(&app{env: env}, true); err != nil || got != dir {
		t.Errorf("system dir %q, %v", got, err)
	}

	file := filepath.Join(t.TempDir(), "PantherClaw")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareBrowserInstallDir(filepath.Join(file, "browser"), true); err == nil || !strings.Contains(err.Error(), "not a folder") {
		t.Errorf("a file in place of the folder: %v", err)
	}
}

// TestHR753_SystemInstallSetsTheFolderAccessList: an existing folder owned
// by Administrators gets the explicit access list (SYSTEM and
// Administrators full control, Users read and execute, nothing inherited),
// and a configuration left there is removed.
func TestHR753_SystemInstallSetsTheFolderAccessList(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "PantherClaw", "browser")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "host-config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Give the folders back to the test so TempDir can remove them.
		sd, _ := windows.SecurityDescriptorFromString("D:(A;OICI;FA;;;WD)")
		dacl, _, _ := sd.DACL()
		for _, d := range []string{dir, filepath.Dir(dir)} {
			_ = windows.SetNamedSecurityInfo(d, windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
		}
	})
	browserDirOwnedBy(t, windows.WinBuiltinAdministratorsSid)
	if err := prepareBrowserInstallDir(dir, true); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Dir(dir), dir} {
		sd, err := windows.GetNamedSecurityInfo(d, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		// The flags may read D:P or D:PAI; the entries must be exactly these.
		got := sd.String()
		flags, aces, _ := strings.Cut(got, "(")
		if !strings.HasPrefix(flags, "D:P") || "("+aces != strings.TrimPrefix(browserSystemDirSDDL, "D:P") {
			t.Errorf("%s access list %s, want %s", d, got, browserSystemDirSDDL)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "host-config.json")); err == nil {
		t.Error("a configuration left in the folder was kept")
	}
}

// TestHR753_TheManifestIsRegisteredUnderChromesKeys: on Windows the
// manifest is named by the default value of Chrome's and Chromium's
// NativeMessagingHosts key for the host name (the test does not write the
// registry).
func TestHR753_TheManifestIsRegisteredUnderChromesKeys(t *testing.T) {
	want := map[string]string{
		"chrome":   `Software\Google\Chrome\NativeMessagingHosts\dev.pantherclaw.browser`,
		"chromium": `Software\Chromium\NativeMessagingHosts\dev.pantherclaw.browser`,
	}
	for b, k := range want {
		if browserHostKeys[b] != k {
			t.Errorf("%s key %q, want %q", b, browserHostKeys[b], k)
		}
	}
	if len(browserHostKeys) != len(want) {
		t.Errorf("keys %v", browserHostKeys)
	}
}

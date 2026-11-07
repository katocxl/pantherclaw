// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build windows

package pclaw

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// browserHostKeys are the registry keys, under HKCU or HKLM, whose default
// value names the host manifest (G0 M33 D979).
var browserHostKeys = map[string]string{
	"chrome":   `Software\Google\Chrome\NativeMessagingHosts\` + browserHostName,
	"chromium": `Software\Chromium\NativeMessagingHosts\` + browserHostName,
}

// browserSystemDirSDDL is the access list of the --system folders and what
// they hold: SYSTEM and Administrators full control, Users read and
// execute, nothing inherited from above.
const browserSystemDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

// browserDirOwnerFn returns a folder's owner; a variable so tests can
// refuse a folder without administrator rights.
var browserDirOwnerFn = browserDirOwner

func browserDirOwner(path string) (*windows.SID, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	return owner, err
}

// prepareBrowserInstallDir makes the install folder. For --system it is
// %ProgramFiles%\PantherClaw\browser: a folder (or its PantherClaw parent)
// that already exists must be owned by SYSTEM or Administrators, else
// someone else could have planted, or could still change, what the browser
// starts. Both get an explicit access list, and the files install-host
// writes are removed first so the new ones carry only that list.
func prepareBrowserInstallDir(dir string, system bool) error {
	if !system {
		return os.MkdirAll(dir, 0o755) //nolint:gosec // G301: the manifest and wrapper must be readable by the browser
	}
	sd, err := windows.SecurityDescriptorFromString("O:BA" + browserSystemDirSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	dirs := []string{filepath.Dir(dir), dir}
	exists := map[string]bool{}
	for _, d := range dirs {
		fi, err := os.Lstat(d)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return err
		case !fi.IsDir() || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0:
			return fmt.Errorf("%s exists and is not a folder: remove it", d)
		}
		owner, err := browserDirOwnerFn(d)
		if err != nil {
			return fmt.Errorf("%s: reading its owner: %w", d, err)
		}
		if !owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return fmt.Errorf("%s exists and is owned by %s, not SYSTEM or Administrators: remove it or take ownership as an administrator", d, account(owner))
		}
		exists[d] = true
	}
	if exists[dir] {
		for _, name := range []string{"host-config.json", "pantherclaw-browser-host.bat", browserHostName + ".json"} {
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	for _, d := range dirs {
		if !exists[d] {
			p, err := windows.UTF16PtrFromString(d)
			if err != nil {
				return err
			}
			sa := windows.SecurityAttributes{SecurityDescriptor: sd}
			sa.Length = uint32(unsafe.Sizeof(sa))
			if err := windows.CreateDirectory(p, &sa); err != nil {
				return fmt.Errorf("%s: %w (--system needs an administrator)", d, err)
			}
		}
		if err := windows.SetNamedSecurityInfo(d, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			return fmt.Errorf("%s: setting its access list: %w", d, err)
		}
	}
	return nil
}

// browserFileOwnedByRoot is for unix; the host does not check modes on
// Windows.
func browserFileOwnedByRoot(os.FileInfo) bool { return false }

// registerBrowserHost writes the manifest next to the configuration and
// registers it for each browser.
func registerBrowserHost(dir string, browsers []string, system bool, manifest []byte) ([]string, error) {
	path := filepath.Join(dir, browserHostName+".json")
	if err := writeFileMode(path, manifest, 0o644); err != nil {
		return nil, err
	}
	root, hive := registry.CURRENT_USER, `HKCU\`
	if system {
		root, hive = registry.LOCAL_MACHINE, `HKLM\`
	}
	written := []string{path}
	for _, b := range browsers {
		k, _, err := registry.CreateKey(root, browserHostKeys[b], registry.SET_VALUE)
		if err != nil {
			return written, err
		}
		err = k.SetStringValue("", path)
		_ = k.Close()
		if err != nil {
			return written, err
		}
		written = append(written, hive+browserHostKeys[b])
	}
	return written, nil
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build windows

package pclaw

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// platformMachineID reads the Windows installation's MachineGuid.
func platformMachineID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer func() { _ = k.Close() }()
	id, _, err := k.GetStringValue("MachineGuid")
	return id, err
}

// platformPrivileged reports whether this process runs as SYSTEM.
func platformPrivileged() bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

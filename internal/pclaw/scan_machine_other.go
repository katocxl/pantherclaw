// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package pclaw

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// platformMachineID reads the system's machine id: /etc/machine-id, or the
// hardware UUID on macOS.
func platformMachineID() (string, error) {
	if runtime.GOOS == "darwin" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err != nil {
			return "", err
		}
		return parseIOPlatformUUID(out)
	}
	return machineIDFromFiles("/etc/machine-id", "/var/lib/dbus/machine-id")
}

// platformPrivileged reports whether this process runs as root.
func platformPrivileged() bool { return os.Geteuid() == 0 }

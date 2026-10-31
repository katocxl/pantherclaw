// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package pclaw

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var ioPlatformUUID = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"`)

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
		m := ioPlatformUUID.FindSubmatch(out)
		if m == nil {
			return "", errors.New("no IOPlatformUUID")
		}
		return string(m[1]), nil
	}
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "" { //nolint:gosec // G304: fixed paths
			return strings.TrimSpace(string(b)), nil
		}
	}
	return "", errors.New("no machine id")
}

// platformPrivileged reports whether this process runs as root.
func platformPrivileged() bool { return os.Geteuid() == 0 }

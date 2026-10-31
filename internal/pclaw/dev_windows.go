// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build windows

package pclaw

import (
	"os/exec"
	"syscall"
)

// detachedProcess is DETACHED_PROCESS: the child has no console of ours.
const detachedProcess = 0x00000008

// detach gives a simulator no console, so that closing the terminal does
// not end it.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build windows

package pclaw

import (
	"context"
	"os/exec"
	"strconv"
	"syscall"
)

const (
	// detachedProcess is DETACHED_PROCESS: the child has no console of ours.
	detachedProcess = 0x00000008
	// processQueryLimited is PROCESS_QUERY_LIMITED_INFORMATION.
	processQueryLimited = 0x1000
)

// detach gives a simulator no console, so that closing the terminal does
// not end it.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess}
}

// processIdentity returns when process pid was created, which tells it from
// a later process given the same id (D134).
func processIdentity(_ context.Context, pid int) (string, error) {
	h, err := syscall.OpenProcess(processQueryLimited, false, uint32(pid)) //nolint:gosec // G115: a process id
	if err != nil {
		return "", err
	}
	defer func() { _ = syscall.CloseHandle(h) }()
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return "", err
	}
	return strconv.FormatInt(created.Nanoseconds(), 10), nil
}

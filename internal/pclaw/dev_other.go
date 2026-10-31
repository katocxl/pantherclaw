// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package pclaw

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// detach puts a simulator in its own session, so that closing the terminal
// does not end it.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// processIdentity returns when process pid started, which tells it from a
// later process given the same id (D134). ps is the one way that works on
// both Linux and macOS.
func processIdentity(ctx context.Context, pid int) (string, error) {
	cmd := exec.CommandContext(ctx, "ps", "-o", "lstart=", "-p", strconv.Itoa(pid)) //nolint:gosec // G204: a number, as an argument of ps
	cmd.Env = append(os.Environ(), "LC_ALL=C")                                      // the date must read the same on every run
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	started := strings.Join(strings.Fields(string(out)), " ")
	if started == "" {
		return "", errors.New("ps reported no start time")
	}
	return started, nil
}

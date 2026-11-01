// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package scan

import "syscall"

const (
	// openNoWait keeps open from waiting for a FIFO's other end.
	openNoWait = syscall.O_NONBLOCK
	// openNoFollow refuses a link in the path's last part.
	openNoFollow = syscall.O_NOFOLLOW
)

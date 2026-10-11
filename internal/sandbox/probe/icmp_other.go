// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !linux

package probe

import (
	"context"
	"net"
)

// The probe runs only in a sandbox's Linux containers (Probe refuses
// elsewhere); off Linux nothing here is ever blocked, so that a misplaced
// run could never pass.
func pingSocket() error                      { return nil }
func icmpEcho(context.Context, net.IP) error { return nil }

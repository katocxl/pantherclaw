// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build windows

package scan_test

import (
	"context"
	"os/exec"
)

// dirLink makes link a junction to the directory target: anyone can make one,
// with no privilege a symbolic link needs.
func dirLink(link, target string) error {
	return exec.CommandContext(context.Background(), "cmd", "/c", "mklink", "/J", link, target).Run()
}

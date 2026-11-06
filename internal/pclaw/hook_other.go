// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package pclaw

import (
	"path/filepath"
	"runtime"
)

// resolveFinal resolves the symbolic links in an existing directory's path;
// on macOS, whose file systems fold case, it also takes the names as the
// file system spells them (G0 M30 D1215).
func resolveFinal(abs string) (string, error) {
	p, err := filepath.EvalSymlinks(abs)
	if err != nil || runtime.GOOS != "darwin" {
		return p, err
	}
	return onDiskSpelling(p), nil
}

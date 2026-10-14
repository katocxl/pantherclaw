// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package pclaw

import "path/filepath"

// resolveFinal resolves the symbolic links in an existing directory's path.
func resolveFinal(abs string) (string, error) { return filepath.EvalSymlinks(abs) }

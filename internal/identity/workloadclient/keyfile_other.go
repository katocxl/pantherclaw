// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package workloadclient

import "os"

// createPrivate creates a new file, never an existing one, that only the
// person can read or write (0600).
func createPrivate(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: operator-chosen path
}

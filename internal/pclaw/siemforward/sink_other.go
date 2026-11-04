// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package siemforward

import "os"

// openOutput opens path for reading and appending, creating it with mode
// 0600 when it is missing; an existing file keeps its mode.
func openOutput(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: the output file the operator names
}

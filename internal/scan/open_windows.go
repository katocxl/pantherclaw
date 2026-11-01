// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build windows

package scan

const (
	// openNoWait is empty here: opening a file never waits on Windows.
	openNoWait = 0
)

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scan

// ReadFile is readFile for tests.
var ReadFile = readFile

// SetAfterCheck runs f between a file's check and its read, and returns what
// restores the seam.
func SetAfterCheck(f func()) func() {
	old := afterCheck
	afterCheck = f
	return func() { afterCheck = old }
}

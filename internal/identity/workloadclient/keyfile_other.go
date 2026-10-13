// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package workloadclient

// private does nothing: the 0600 mode already keeps the key file the
// person's own.
func private(string) error { return nil }

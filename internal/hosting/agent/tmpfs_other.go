// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !linux

package agent

// checkTmpfs fails: a hosting host is Linux, and nothing else can prove the
// private root is a memory file system (HR-502).
func checkTmpfs(string) error { return ErrNotTmpfs }

// chownTo is a no-op where hosts never run.
func chownTo(string, int) error { return nil }

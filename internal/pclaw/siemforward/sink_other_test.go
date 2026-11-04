// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build !windows

package siemforward

import (
	"os"
	"testing"
)

// ownerOnly checks the file's mode is 0600.
func ownerOnly(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("created %v, want 0600", st.Mode().Perm())
	}
}

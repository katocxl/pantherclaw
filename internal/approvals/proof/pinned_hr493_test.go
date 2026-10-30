// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package proof_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	"github.com/katocxl/pantherclaw/internal/approvals/proof/prooftest"
	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
)

// TestHR493_ApproverKeysAreNeverServedStale (ADR-0040, approver keys):
// the pinned file is read again on the very next verification after its
// size or modification time changes, with no time-based cache, and a file
// that stops loading refuses at once (fail closed).
// Covers: HR-493
func TestHR493_ApproverKeysAreNeverServedStale(t *testing.T) {
	bob := prooftest.NewApprover(t, webauthntest.ES256)
	path := filepath.Join(t.TempDir(), "approver-keys.json")
	if err := os.WriteFile(path, prooftest.File(t, org, bob), 0o600); err != nil {
		t.Fatal(err)
	}
	b := prooftest.Binding(t, requested, effective)
	a := prooftest.Approval(b, bob.Assert(t, b.Hash[:], 0))
	p := proof.NewPinned(path, org)
	if err := p.Verify(a, want); err != nil {
		t.Fatalf("the installed file: %v", err)
	}
	touch := func(content []byte, at time.Time) {
		t.Helper()
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, at, at); err != nil {
			t.Fatal(err)
		}
	}
	// The key is removed: the next verification refuses.
	carol := prooftest.NewApprover(t, webauthntest.ES256)
	touch(prooftest.File(t, org, carol), time.Now().Add(time.Minute))
	refused(t, p.Verify(a, want), "the very next verification after the key was removed")
	// The key is back: accepted again at once.
	touch(prooftest.File(t, org, bob), time.Now().Add(2*time.Minute))
	if err := p.Verify(a, want); err != nil {
		t.Fatalf("the key restored: %v", err)
	}
	// The file stops loading, then goes: refused each time.
	touch([]byte("{"), time.Now().Add(3*time.Minute))
	refused(t, p.Verify(a, want), "a file that no longer loads")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	refused(t, p.Verify(a, want), "a removed file")
}

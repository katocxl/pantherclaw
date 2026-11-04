// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package signals

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// TestHR664_PlaybookNoteKinds: each playbook note keeps its old audit kind
// byte for byte ("signals.playbook_" + the note), and an unknown note is
// refused without a write (HR-664).
func TestHR664_PlaybookNoteKinds(t *testing.T) {
	t.Parallel()
	notes := []string{"skipped", "failed"}
	if len(playbookNoteKinds) != len(notes) {
		t.Errorf("playbookNoteKinds has %d notes, want %d", len(playbookNoteKinds), len(notes))
	}
	for _, n := range notes {
		if got, want := playbookNoteKinds[n], "signals.playbook_"+n; got != want {
			t.Errorf("playbookNoteKinds[%s] = %q, want %q", n, got, want)
		}
	}
	if err := (&Service{}).playbookNote(t.Context(), db.TenantTx{}, Received{}, "paused", ""); err == nil {
		t.Error("playbookNote(paused) = nil, want an error")
	}
}

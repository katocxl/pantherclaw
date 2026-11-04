// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"testing"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// TestHR664_ChangeKinds: each recommendation change keeps its old audit
// kind byte for byte ("recommendation." + the change), and an unknown
// change is refused before anything is written (HR-664).
func TestHR664_ChangeKinds(t *testing.T) {
	t.Parallel()
	events := []string{"dismissed", "undismissed"}
	if len(changeKinds) != len(events) {
		t.Errorf("changeKinds has %d changes, want %d", len(changeKinds), len(events))
	}
	for _, e := range events {
		if got, want := changeKinds[e], "recommendation."+e; got != want {
			t.Errorf("changeKinds[%s] = %q, want %q", e, got, want)
		}
	}
	person := evdomain.Actor{Type: "user", ID: "u"}
	if err := recordChange(t.Context(), db.TenantTx{}, person, "identity.ci_workload", "snoozed", ""); err == nil {
		t.Error("recordChange(snoozed) = nil, want an error")
	}
}

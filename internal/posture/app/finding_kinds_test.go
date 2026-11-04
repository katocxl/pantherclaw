// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"strings"
	"testing"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR664_FindingKinds: every finding event a person can cause keeps
// its old audit kind byte for byte ("posture.finding_" + the lowercased
// event), and an unknown event is refused without a write (HR-664).
func TestHR664_FindingKinds(t *testing.T) {
	t.Parallel()
	events := []string{"ASSIGNED", "TESTING", "ACCEPTED", "EVIDENCE_INCOMPLETE", "REOPENED", "NOTE"}
	if len(findingKinds) != len(events) {
		t.Errorf("findingKinds has %d events, want %d", len(findingKinds), len(events))
	}
	for _, e := range events {
		if got, want := findingKinds[e], "posture.finding_"+strings.ToLower(e); got != want {
			t.Errorf("findingKinds[%s] = %q, want %q", e, got, want)
		}
	}
	person := evdomain.Actor{Type: "user", ID: "u"}
	if err := auditMove(t.Context(), db.TenantTx{}, ids.UUID{1}, "RENAMED", person, "", map[string]string{}); err == nil {
		t.Error("auditMove(RENAMED) = nil, want an error")
	}
}

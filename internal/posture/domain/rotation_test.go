// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/posture/domain"
)

// TestT224_UnconfirmedRotationIsAFinding: a rotation that has awaited the
// old key's removal for more than 24 hours is an unconfirmed_rotation
// finding of its connection; one whose rollback window is still open, or
// that awaits for less, is none; and once the rotation leaves those states
// (no longer derived) a complete recomputation remediates the finding
// (D259).
// Covers: F424
func TestT224_UnconfirmedRotationIsAFinding(t *testing.T) {
	conn, rot := ids.NewV7(), ids.NewV7()
	derive := func(since time.Time) []domain.Candidate {
		return domain.Derive(domain.Inputs{Now: now, Rotations: []domain.RotationInfo{{ID: rot, Connection: conn, Name: "gh", Since: since}}})
	}
	for name, since := range map[string]time.Time{
		"window still open": now.Add(time.Hour), "awaiting 23 hours": now.Add(-23 * time.Hour), "exactly 24 hours": now.Add(-24 * time.Hour),
	} {
		if c := derive(since); len(c) != 0 {
			t.Fatalf("%s: %+v", name, c)
		}
	}
	c := derive(now.Add(-25 * time.Hour))
	if len(c) != 1 || c[0].Kind != domain.UnconfirmedRotation || c[0].RootCause != "connection:"+conn.String() || *c[0].Connection != conn ||
		c[0].Detail["rotation"] != rot.String() || len(c[0].Paths) != 1 {
		t.Fatalf("awaiting 25 hours: %+v", c)
	}
	f := domain.Finding{ID: ids.NewV7(), Kind: domain.UnconfirmedRotation, Fingerprint: c[0].Fingerprint(), State: domain.Open, Paths: c[0].Paths, Connection: &conn}
	if acts := domain.Reconcile([]domain.Finding{f}, c, domain.Snapshot{Now: now}); len(acts) != 1 || acts[0].Kind != domain.ActSeen {
		t.Fatalf("still unconfirmed: %+v", acts)
	}
	if acts := domain.Reconcile([]domain.Finding{f}, nil, domain.Snapshot{Now: now}); len(acts) != 1 || acts[0].Kind != domain.ActRemediate {
		t.Fatalf("confirmed: %+v", acts)
	}
}

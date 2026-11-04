// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine_test

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// TestHR680_LastInputIsTheNewestMatchingEvent: per rule, the newest
// occurred_at among the batch's events of a kind it reads, sequence steps
// included; a rule that read nothing gets no entry, and Reflex's own entries
// are never input (G0 M28 D716).
// Covers: F960, HR-680
func TestHR680_LastInputIsTheNewestMatchingEvent(t *testing.T) {
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	set := []*engine.Compiled{
		{Rule: &rules.Rule{ID: "pc.a", On: []string{"audit.security.*"}}},
		{Rule: &rules.Rule{ID: "pc.b", On: []string{"transaction.decided"}}},
		{Rule: &rules.Rule{ID: "pc.seq", Sequence: &rules.Sequence{Steps: []rules.Step{
			{On: []string{"audit.agent.created"}}, {On: []string{"audit.grant.issued"}},
		}}}},
		{Rule: &rules.Rule{ID: "pc.none", On: []string{"audit.nothing"}}},
	}
	events := []feed.Event{
		{Kind: "audit.security.kill_switch_engaged", OccurredAt: t0.Add(2 * time.Minute)},
		{Kind: "audit.security.kill_switch_engaged", OccurredAt: t0}, // older, later in the batch
		{Kind: "audit.grant.issued", OccurredAt: t0.Add(time.Minute)},
		{Kind: "reflex.alert.raised", OccurredAt: t0.Add(time.Hour)},
	}
	got := engine.LastInputs(set, events)
	want := map[string]time.Time{"pc.a": t0.Add(2 * time.Minute), "pc.seq": t0.Add(time.Minute)}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for id, at := range want {
		if !got[id].Equal(at) {
			t.Errorf("%s: %v, want %v", id, got[id], at)
		}
	}
}

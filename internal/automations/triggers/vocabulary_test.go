// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

func TestVocabularyMeansItsFeedKinds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		e    feed.Event
		f    Facts
		want bool
	}{
		{VocabActionDenied, feed.Event{Kind: "receipt.decision", Decision: "DENY"}, Facts{}, true},
		{VocabActionDenied, feed.Event{Kind: "receipt.decision", Decision: "ALLOW"}, Facts{}, false},
		{VocabActionHeld, feed.Event{Kind: "receipt.decision", Decision: "HOLD"}, Facts{}, true},
		{VocabActionDecided, feed.Event{Kind: "receipt.decision", Decision: "ALLOW"}, Facts{}, true},
		{VocabAgentDiscovered, feed.Event{Kind: "audit.agent.discovered"}, Facts{}, true},
		{VocabAgentDiscovered, feed.Event{Kind: "audit.agent.claimed"}, Facts{}, false},
		// Continuous discovery (G0 M17 D116). Covers: PN-001.3
		{VocabDiscoveryChanged, feed.Event{Kind: "audit.agent.discovery_changed"}, Facts{}, true},
		{VocabDiscoveryVanished, feed.Event{Kind: "audit.agent.discovery_vanished"}, Facts{}, true},
		{VocabDiscoveryVanished, feed.Event{Kind: "audit.agent.discovery_reappeared"}, Facts{}, false},
		{VocabAutomationFinished, feed.Event{Kind: "audit.automation.execution_finished"}, Facts{}, true},
		{VocabAutomationFinished, feed.Event{Kind: "audit.automation.finished"}, Facts{}, false},
		{VocabCoverageLost, feed.Event{Kind: "coverage.snapshot", Attrs: map[string]string{"previous_state": "ENFORCED", "state": "PARTIAL"}}, Facts{}, true},
		{VocabCoverageLost, feed.Event{Kind: "coverage.snapshot", Attrs: map[string]string{"previous_state": "PARTIAL", "state": "ENFORCED"}}, Facts{}, false},
		{VocabCoverageLost, feed.Event{Kind: "coverage.invalidation"}, Facts{}, true},
		{VocabIncidentOpened, feed.Event{Kind: "reflex.incident", Outcome: "OPEN"}, Facts{}, true},
		{VocabIncidentOpened, feed.Event{Kind: "reflex.incident", Outcome: "CLOSED"}, Facts{}, false},
		{VocabCaseClosed, feed.Event{Kind: "reflex.case"}, Facts{CaseClosed: true}, true},
		{VocabCaseClosed, feed.Event{Kind: "reflex.case"}, Facts{}, false},
		{"not.a.name", feed.Event{Kind: "receipt.decision", Decision: "DENY"}, Facts{}, false},
	} {
		if got := Means(tc.name, tc.e, tc.f); got != tc.want {
			t.Errorf("%s on %s: %v, want %v", tc.name, tc.e.Kind, got, tc.want)
		}
	}
	if len(Vocabulary()) != 16 || !KnownEvent(VocabAgentDiscovered) || KnownEvent("agent.change") {
		t.Fatal("vocabulary")
	}
}

func TestDaysNoteExplainsIntersectingDays(t *testing.T) {
	t.Parallel()
	if n := DaysNote("0 0 */2 * MON"); !strings.Contains(n, "must match both") {
		t.Fatalf("note: %q", n)
	}
	for _, expr := range []string{"0 0 * * MON", "0 0 13 * FRI", "0 0 */2 * *", "not a cron"} {
		if n := DaysNote(expr); n != "" {
			t.Errorf("%q: %q", expr, n)
		}
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"strings"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// TestAReceiptOfAHoldIsAHeldAction reads each decision the way production does:
// a ledger body of the fields finalize writes, through the feed.
func TestAReceiptOfAHoldIsAHeldAction(t *testing.T) {
	t.Parallel()
	for decision, held := range map[adomain.Decision]bool{
		adomain.RequireApproval: true, adomain.RequireStepUp: true,
		adomain.Allow: false, adomain.AllowWithObligations: false, adomain.Deny: false, adomain.CannotAuthorize: false,
	} {
		body, err := evdomain.CanonicalBody(map[string]string{
			"txn": "018f0000-0000-7000-8000-000000000001", "evaluation": "1", "decision": string(decision),
			"act": "action-hash", "reason": "APPROVAL_REQUIRED", "receipt_sha256": strings.Repeat("0", 64),
		})
		if err != nil {
			t.Fatal(err)
		}
		e, err := feed.Normalize(kindDecision, "gateway", "gateway-1", time.Now(), body)
		if err != nil {
			t.Fatal(err)
		}
		if got := Means(VocabActionHeld, e, Facts{}); got != held {
			t.Errorf("%s held = %v, want %v", decision, got, held)
		}
		if !Means(VocabActionDecided, e, Facts{}) {
			t.Errorf("%s is not a decided action", decision)
		}
	}
}

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
		{VocabActionHeld, feed.Event{Kind: "receipt.decision", Decision: "REQUIRE_APPROVAL"}, Facts{}, true},
		{VocabActionHeld, feed.Event{Kind: "receipt.decision", Decision: "REQUIRE_STEP_UP"}, Facts{}, true},
		{VocabActionHeld, feed.Event{Kind: "receipt.decision", Decision: "ALLOW"}, Facts{}, false},
		{VocabActionHeld, feed.Event{Kind: "receipt.decision", Decision: "DENY"}, Facts{}, false},
		{VocabActionHeld, feed.Event{Kind: "receipt.decision", Decision: "HOLD"}, Facts{}, false},
		{VocabActionHeld, feed.Event{Kind: "receipt.effect", Decision: "REQUIRE_APPROVAL"}, Facts{}, false},
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

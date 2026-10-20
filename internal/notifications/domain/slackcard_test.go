// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/notifications/domain"
)

func facts(level string) domain.CardFacts {
	return domain.CardFacts{
		Level: level, Kind: "ACTION", Consequence: "irreversible", State: "PENDING",
		ExpiresAt: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC), RequestID: "0199f0aa-1111-7222-8333-444455556666",
		Link:      "https://pc.example/approvals/0199f0aa-1111-7222-8333-444455556666?org=0199f0aa-0000-7000-8000-000000000001",
		Operation: "payments.refund.create", Agent: "billing-bot\u202e<@U123>", Environment: "production",
	}
}

func render(t *testing.T, c domain.SlackCard) string {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestHR313_CardOnlyLinksToTheApprovalPage: an open card's only
// interactive element is one url button to the approval page; a closed
// card has no button and no link (D23).
func TestHR313_CardOnlyLinksToTheApprovalPage(t *testing.T) {
	f := facts(domain.SlackMinimal)
	open := domain.OpenCard(f)
	var buttons int
	for _, b := range open.Blocks {
		if b.Type != "actions" {
			continue
		}
		for _, e := range b.Elements {
			if e.Type != "button" || e.URL != f.Link {
				t.Fatalf("element %+v", e)
			}
			buttons++
		}
	}
	if buttons != 1 || !strings.Contains(open.Text, f.Link) {
		t.Fatalf("buttons %d, text %q", buttons, open.Text)
	}
	for _, typ := range []string{"input", "static_select", "checkboxes", "radio_buttons", "overflow", "\"value\"", "\"confirm\""} {
		if strings.Contains(render(t, open), typ) {
			t.Fatalf("open card has %s", typ)
		}
	}
	for _, state := range []string{"APPROVED", "DECLINED", "EXPIRED", "INVALIDATED", "CANCELLED"} { //nolint:misspell // a state name
		f.State = state
		closed := render(t, domain.ClosedCard(f))
		if strings.Contains(closed, "button") || strings.Contains(closed, "/approvals/") || strings.Contains(closed, "https://") {
			t.Fatalf("%s: closed card links: %s", state, closed)
		}
		if !domain.CardIsClosed(state) {
			t.Fatalf("%s not closed", state)
		}
	}
	if domain.CardIsClosed("PENDING") || domain.CardIsClosed("EVIDENCE_REQUESTED") {
		t.Fatal("a waiting request is closed")
	}
}

// TestHR314_CardDataByLevel: MINIMAL shows the kind, the consequence, the
// expiry and a short reference; SUMMARY adds the operation id, the agent
// and the environment, cleaned; neither shows the full id or anything
// else (D23).
func TestHR314_CardDataByLevel(t *testing.T) {
	// The full id appears only inside the deep link.
	minimal := strings.ReplaceAll(render(t, domain.OpenCard(facts(domain.SlackMinimal))), facts("").Link, "LINK")
	for _, want := range []string{"Approval needed", "Agent action", "Irreversible", "2026-10-17 12:00 UTC", "Reference: 55556666"} {
		if !strings.Contains(minimal, want) {
			t.Fatalf("minimal lacks %q: %s", want, minimal)
		}
	}
	for _, no := range []string{"payments.refund.create", "billing-bot", "production", "0199f0aa-1111", "mrkdwn"} {
		if strings.Contains(minimal, no) {
			t.Fatalf("minimal shows %q: %s", no, minimal)
		}
	}
	summary := render(t, domain.OpenCard(facts(domain.SlackSummary)))
	for _, want := range []string{"Operation: payments.refund.create", "Agent: billing-bot<@U123>", "Environment: production"} {
		if !strings.Contains(summary, strings.ReplaceAll(strings.ReplaceAll(want, "<", `<`), ">", `>`)) && !strings.Contains(summary, want) {
			t.Fatalf("summary lacks %q: %s", want, summary)
		}
	}
	if strings.Contains(summary, "\u202e") || strings.Contains(summary, "mrkdwn") {
		t.Fatalf("summary not cleaned or not plain text: %s", summary)
	}
	f := facts(domain.SlackSummary)
	f.Simulated = true
	if c := domain.OpenCard(f); !strings.HasPrefix(c.Blocks[0].Text.Text, "[SIMULATED] ") {
		t.Fatalf("simulated header %q", c.Blocks[0].Text.Text)
	}
}

func TestM14_CardEvents(t *testing.T) {
	for typ, want := range map[string]domain.CardEvent{
		"approval.requested": domain.CardPost, "automation.gate_requested": domain.CardPost,
		"approval.decided": domain.CardClose, "approval.expired": domain.CardClose, "approval.invalidated": domain.CardClose,
		"automation.gate_decided": domain.CardClose, "approval.escalated": domain.CardEscalate, "channel.test": domain.CardTest,
		"approval.reminder": domain.CardNone, "approval.unroutable": domain.CardNone, "security.credential_registered": domain.CardNone,
		"approval.multi_person_completed": domain.CardNone,
	} {
		if got := domain.CardEventOf(typ); got != want {
			t.Errorf("%s: %q, want %q", typ, got, want)
		}
	}
	if r := domain.EscalationReply(2); r.Text != "Escalated (step 2)" || len(r.Blocks) != 0 {
		t.Fatalf("reply %+v", r)
	}
}

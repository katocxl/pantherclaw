// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/ticketsync/domain"
)

// TestHR527_ContainmentAndRestorationNeverGoToTheTicket: containment and
// restoration are PantherClaw's whatever an organization stored, and
// cannot be chosen (D264); state and severity default to PantherClaw and
// may be given to the ticket system; the other fields default to the
// ticket system and may be taken back.
//
// Covers: F545
func TestHR527_ContainmentAndRestorationNeverGoToTheTicket(t *testing.T) {
	stored := domain.Owners{}
	for _, f := range domain.Fields {
		stored[f] = domain.OwnerTicket
	}
	for _, f := range []domain.Field{domain.FieldContainment, domain.FieldRestoration} {
		if !f.Locked() || f.Movable() || stored.Of(f) != domain.OwnerPantherClaw || domain.DefaultOwner(f) != domain.OwnerPantherClaw {
			t.Errorf("%s is not always PantherClaw's", f)
		}
	}
	for _, f := range []domain.Field{domain.FieldState, domain.FieldSeverity} {
		if f.Locked() || !f.Movable() || domain.DefaultOwner(f) != domain.OwnerPantherClaw || stored.Of(f) != domain.OwnerTicket {
			t.Errorf("%s does not default to PantherClaw or cannot be given away", f)
		}
	}
	for _, f := range []domain.Field{domain.FieldAssignee, domain.FieldLabels, domain.FieldPriority, domain.FieldComments} {
		if f.Locked() || domain.DefaultOwner(f) != domain.OwnerTicket || (domain.Owners{}).Of(f) != domain.OwnerTicket {
			t.Errorf("%s does not default to the ticket system", f)
		}
		if (domain.Owners{f: domain.OwnerPantherClaw}).Of(f) != domain.OwnerPantherClaw {
			t.Errorf("%s cannot be taken back", f)
		}
	}
	if (domain.Owners{}).Of("unknown") != domain.OwnerPantherClaw {
		t.Error("an unknown field is not PantherClaw's")
	}
}

// TestHR528_DecideDropsOwnedChanges: an inbound change to a
// PantherClaw-owned field is ignored with a recorded text, a ticket-owned
// change is mirrored, and a status moved to Done is only noted; no verdict
// is anything else (HR-527).
//
// Covers: F545
func TestHR528_DecideDropsOwnedChanges(t *testing.T) {
	changes := []domain.Change{
		{Field: domain.FieldState, To: "Done", Done: true},
		{Field: domain.FieldState, To: "In Progress"},
		{Field: domain.FieldSeverity, To: "Low"},
		{Field: domain.FieldContainment, To: "Lifted"},
		{Field: domain.FieldRestoration, To: "Restored"},
		{Field: domain.FieldAssignee, To: "Alice"},
		{Field: domain.FieldPriority, To: "High"},
		{Field: "unknown", To: "x"},
	}
	got := domain.Decide(domain.Owners{}, "SEC-7", changes, &domain.Comment{Author: "Bob", Body: "fixed\x00 it"})
	want := []domain.Action{
		domain.ActionNote, domain.ActionIgnore, domain.ActionIgnore, domain.ActionIgnore, domain.ActionIgnore,
		domain.ActionMirror, domain.ActionMirror, domain.ActionMirror,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d verdicts, want %d: %+v", len(got), len(want), got)
	}
	for i, v := range got {
		if v.Action != want[i] {
			t.Errorf("verdict %d (%s) is %s, want %s", i, v.Field, v.Action, want[i])
		}
		if !strings.Contains(v.Text, "SEC-7") || strings.ContainsRune(v.Text, 0) {
			t.Errorf("verdict %d text %q", i, v.Text)
		}
	}
	if !strings.Contains(got[0].Text, "never restores authority") {
		t.Errorf("a Done note does not say so: %q", got[0].Text)
	}
	// Comments the organization took back are ignored, not mirrored.
	got = domain.Decide(domain.Owners{domain.FieldComments: domain.OwnerPantherClaw}, "SEC-7", nil, &domain.Comment{Body: "hi"})
	if len(got) != 1 || got[0].Action != domain.ActionIgnore {
		t.Fatalf("an owned comment: %+v", got)
	}
}

func TestClean(t *testing.T) {
	if got := domain.Clean(" a\n\tb\xe2\x80\xae c ", 100); got != "a b c" {
		t.Errorf("Clean = %q", got)
	}
	if got := domain.Clean(strings.Repeat("x", 300), 10); len([]rune(got)) != 10 || !strings.HasSuffix(got, "…") {
		t.Errorf("Clean cut = %q", got)
	}
}

const jiraDone = `{"timestamp":1793361600000,"webhookEvent":"jira:issue_updated",
 "issue":{"key":"SEC-7","fields":{"updated":"2026-10-30T12:00:00.000+0000","status":{"statusCategory":{"key":"done"}}}},
 "changelog":{"items":[{"field":"status","fromString":"To Do","toString":"Done"},{"field":"Flagged","toString":"x"},
 {"field":"assignee","toString":"Alice"}]}}`

func TestParseJiraWebhook(t *testing.T) {
	ev, err := domain.ParseJiraWebhook([]byte(jiraDone))
	if err != nil {
		t.Fatal(err)
	}
	if ev.IssueKey != "SEC-7" || !ev.At.Equal(time.UnixMilli(1793361600000)) || len(ev.Changes) != 2 {
		t.Fatalf("event %+v", ev)
	}
	if c := ev.Changes[0]; c.Field != domain.FieldState || !c.Done || c.To != "Done" {
		t.Fatalf("status change %+v", c)
	}
	ev, err = domain.ParseJiraWebhook([]byte(`{"timestamp":1,"webhookEvent":"comment_created","issue":{"key":"SEC-7"},
		"comment":{"id":"1","author":{"displayName":"Bob"},"body":"hello"}}`))
	if err != nil || ev.Comment == nil || ev.Comment.Body != "hello" || ev.Comment.Author != "Bob" {
		t.Fatalf("comment event %+v %v", ev, err)
	}
	for _, bad := range []string{
		`{}`, `not json`, `{"webhookEvent":"jira:issue_deleted","timestamp":1,"issue":{"key":"SEC-7"}}`,
		`{"webhookEvent":"jira:issue_updated","timestamp":1,"issue":{"key":"sec-7"}}`,
		`{"webhookEvent":"jira:issue_updated","issue":{"key":"SEC-7","fields":{"updated":"yesterday"}}}`,
	} {
		if _, err := domain.ParseJiraWebhook([]byte(bad)); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

// TestT227_ForgedWebhookSignature: a webhook verifies only with the
// configuration's secret (or the previous one); a forged, altered or
// unsigned body does not.
//
// Covers: F545
func TestT227_ForgedWebhookSignature(t *testing.T) {
	secret, prev := []byte("s3cret-0123456789"), []byte("old-secret-012345")
	body := []byte(jiraDone)
	sig := domain.SignJira(secret, body)
	if !domain.VerifyJiraSignature(sig, body, secret) || !domain.VerifyJiraSignature(domain.SignJira(prev, body), body, secret, prev) {
		t.Fatal("a valid signature does not verify")
	}
	for name, c := range map[string]struct {
		sig  string
		body []byte
	}{
		"another key": {domain.SignJira([]byte("attacker-key-0123"), body), body},
		"altered":     {sig, append([]byte{' '}, body...)},
		"unsigned":    {"", body},
		"no scheme":   {strings.TrimPrefix(sig, "sha256="), body},
		"short":       {"sha256=abcd", body},
	} {
		if domain.VerifyJiraSignature(c.sig, c.body, secret, nil) {
			t.Errorf("%s verifies", name)
		}
	}
}

// TestHR527_ATicketOwnedStateIsOnlyMirrored: when the organization gave
// state to the ticket system, a status change, Done included, is a mirror
// note that says it restores nothing; containment stays ignored.
//
// Covers: F545
func TestHR527_ATicketOwnedStateIsOnlyMirrored(t *testing.T) {
	own := domain.Owners{domain.FieldState: domain.OwnerTicket, domain.FieldContainment: domain.OwnerTicket}
	got := domain.Decide(own, "SEC-7", []domain.Change{
		{Field: domain.FieldState, To: "Done", Done: true}, {Field: domain.FieldContainment, To: "Lifted"},
	}, nil)
	if len(got) != 2 || got[0].Action != domain.ActionMirror || got[1].Action != domain.ActionIgnore {
		t.Fatalf("verdicts %+v", got)
	}
	if !strings.Contains(got[0].Text, "never restores authority") {
		t.Fatalf("a mirrored state does not say it restores nothing: %q", got[0].Text)
	}
}

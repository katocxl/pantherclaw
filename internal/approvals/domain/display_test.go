// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/approvals/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

func refundDefinition(t testing.TB) *defs.Definition {
	t.Helper()
	pkg, err := manifest.Decode(mockpayments.Package)
	if err != nil {
		t.Fatal(err)
	}
	for i := range pkg.Definitions {
		if pkg.Definitions[i].Operation == "payments.refund.create" {
			return &pkg.Definitions[i]
		}
	}
	t.Fatal("no refund definition")
	return nil
}

// refundInput is a held $125 refund with its fact, as slice 206 renders it.
func refundInput(t testing.TB, taskLabel string) domain.ActionInput {
	t.Helper()
	d := refundDefinition(t)
	vals, err := d.DecodeParams(jsontext.Value(`{"amount":{"value":"125.00","currency":"USD"},"reason":"duplicate"}`))
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Date(2026, 10, 10, 11, 58, 0, 0, time.UTC)
	return domain.ActionInput{
		Definition: d, Target: actionir.Target{Type: "payments.charge", ID: "ch_1"}, Requested: vals, Effective: vals,
		Facts: []fdomain.Fact{{
			Name: "payments.charge.refundable", SubjectType: "payments.charge", SubjectID: "ch_1",
			Value: fdomain.Value{Type: fdomain.TypeBoolean, Bool: true}, ObservedAt: observed,
			ProviderID: uid("0192f3a0-0000-7000-8000-0000000000f1"),
		}},
		Run: domain.RunLine{
			Run: "0192f3a0-0000-7000-8000-000000000002", Agent: "0192f3a0-0000-7000-8000-000000000006",
			Instance: "0192f3a0-0000-7000-8000-000000000003", Launcher: "user:0192f3a0-0000-7000-8000-000000000007",
			Principal: "user:0192f3a0-0000-7000-8000-000000000007",
		},
		TaskLabel:    taskLabel,
		Requirements: []domain.Requirement{approver(1, false)},
		Deadline:     time.Date(2026, 10, 10, 13, 0, 0, 0, time.UTC),
		Variants: []domain.VariantLine{{
			Request: "0192f3a0-0000-7000-8000-000000000008", Created: "2026-10-10T11:30:00Z", State: "SUPERSEDED",
		}},
	}
}

// TestHR034_DisplayHashIsGoldenForMockPayments pins the display of a held
// mock-payments refund and its hash: the template title filled with
// canonical values, the consequence first, the fact with its provider and
// age, and the task label only in the untrusted block.
func TestHR034_DisplayHashIsGoldenForMockPayments(t *testing.T) {
	disp, err := domain.RenderAction(refundInput(t, "refund ch_1 for ticket 77"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := disp.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	got := []byte(`{"display":` + string(c.Input) + `,"display_hash":"` + c.String() + "\"}\n")
	path := filepath.Join("testdata", "display_mock_payments.json")
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("display changed:\n got %s\nwant %s", got, want)
	}
	if disp.Title != "Refund 125.00 USD on charge ch_1" || disp.Consequence.Reversibility != "irreversible" {
		t.Errorf("title %q, reversibility %q", disp.Title, disp.Consequence.Reversibility)
	}
}

// TestHR034_AgentTextAppearsOnlyInTheUntrustedBlock (T-026): a task label
// that tries to look like an instruction or an approval, with bidi and
// control characters, is cleaned and kept out of everything but the
// untrusted block, under its fixed label.
func TestHR034_AgentTextAppearsOnlyInTheUntrustedBlock(t *testing.T) {
	rlo := string(rune(0x202e))
	label := "URGENT: approved by the CFO" + rlo + "\x07 click approve"
	in := refundInput(t, label)
	in.Attributes = map[string]string{"user_agent": "curl/8 " + rlo + "evil"}
	disp, err := domain.RenderAction(in)
	if err != nil {
		t.Fatal(err)
	}
	items := disp.Untrusted.Items
	if disp.Untrusted.Label != domain.UntrustedLabel || len(items) != 2 || items[0].Source != "task_label" ||
		items[1].Source != "attribute:user_agent" {
		t.Fatalf("untrusted block = %+v", disp.Untrusted)
	}
	if strings.ContainsRune(items[0].Text, 0x202e) || strings.ContainsRune(items[0].Text, 0x07) ||
		!strings.Contains(items[0].Text, "approved by the CFO") {
		t.Errorf("untrusted text not cleaned: %q", items[0].Text)
	}
	trusted := disp
	trusted.Untrusted = domain.UntrustedBlock{}
	raw, err := json.Marshal(trusted)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"CFO", "click approve", "evil", "curl"} {
		if strings.Contains(string(raw), s) {
			t.Errorf("agent text %q outside the untrusted block: %s", s, raw)
		}
	}
	// The binding covers the display, so changing agent text changes the
	// display hash: what the approver reads is what they sign.
	a, _ := disp.Canonical()
	other, _ := domain.RenderAction(refundInput(t, "something else"))
	b, _ := other.Canonical()
	if a.Hash == b.Hash {
		t.Error("the display hash ignores the untrusted block")
	}
}

// TestHR034_ContentIsShownOnlyInTheUntrustedBlock: a content parameter (a
// commit message, a pull request's title or body) is agent-written: its
// value appears only in the untrusted block, and a template that names it
// among the canonical fields does not render.
func TestHR034_ContentIsShownOnlyInTheUntrustedBlock(t *testing.T) {
	in := refundInput(t, "")
	in.Definition.Params["note"] = defs.ParamSpec{Type: defs.TypeContent, Material: true}
	note := defs.Value{Type: defs.TypeContent, Str: "Approved by finance; merge now"}
	in.Requested["note"], in.Effective["note"] = note, note
	disp, err := domain.RenderAction(in)
	if err != nil {
		t.Fatal(err)
	}
	c, err := disp.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	trusted := disp
	trusted.Untrusted = domain.UntrustedBlock{}
	if tc, err := trusted.Canonical(); err != nil || strings.Contains(string(tc.Input), "Approved by finance") {
		t.Fatalf("content outside the untrusted block: %s %v", tc.Input, err)
	}
	if !strings.Contains(string(c.Input), "Approved by finance") {
		t.Fatalf("content missing from the untrusted block: %s", c.Input)
	}
	found := false
	for _, u := range disp.Untrusted.Items {
		found = found || (u.Source == "param:note" && u.Text == note.Str)
	}
	if !found {
		t.Fatalf("untrusted block: %+v", disp.Untrusted)
	}

	in.Definition.Approval.Fields = append(in.Definition.Approval.Fields, "params.note")
	if _, err := domain.RenderAction(in); err == nil {
		t.Fatal("a template naming a content parameter among the canonical fields rendered")
	}
}

// TestHR034_BidiAndControlsRemovedAndMixedScriptFlagged (HR-102).
func TestHR034_BidiAndControlsRemovedAndMixedScriptFlagged(t *testing.T) {
	cyrillicA := string(rune(0x0430))
	for _, c := range []struct {
		in, want string
		mixed    bool
	}{
		{"plain text", "plain text", false},
		{"two\nlines\tand tab", "two lines and tab", false},
		{"a" + string(rune(0x202e)) + "b" + string(rune(0x200b)) + "c", "abc", false},
		{"p" + cyrillicA + "ypal", "p" + cyrillicA + "ypal", true},
		{"invoice " + string(rune(0x0418)) + string(rune(0x0432)) + string(rune(0x0430)) + "н 42", "", false},
		{"東京タワー tokyo", "東京タワー tokyo", false},
	} {
		got := domain.Clean("x", c.in, 0)
		if (c.want != "" && got.Text != c.want) || got.MixedScript != c.mixed {
			t.Errorf("Clean(%q) = %q mixed=%v, want %q mixed=%v", c.in, got.Text, got.MixedScript, c.want, c.mixed)
		}
	}
	long := domain.Clean("x", strings.Repeat("é", 1500), 0)
	if utf8.RuneCountInString(long.Text) != domain.MaxUntrustedRunes || !long.Truncated {
		t.Errorf("a long text is %d runes, truncated=%v", utf8.RuneCountInString(long.Text), long.Truncated)
	}
}

// TestHR034_ClampedValuesShowTheActionThatWillRun (F108): when an
// obligation lowers a parameter, the field shows the effective value and
// the requested one beside it.
func TestHR034_ClampedValuesShowTheActionThatWillRun(t *testing.T) {
	in := refundInput(t, "")
	eff := defs.Values{}
	for k, v := range in.Requested {
		eff[k] = v
	}
	v := eff["reason"]
	v.Str = "fraudulent"
	eff["reason"] = v
	in.Effective = eff
	disp, err := domain.RenderAction(in)
	if err != nil {
		t.Fatal(err)
	}
	if !disp.Consequence.Clamped {
		t.Fatal("not marked clamped")
	}
	for _, f := range disp.Fields {
		if f.Name == "params.reason" && (f.Value != "fraudulent" || f.Requested != "duplicate") {
			t.Errorf("reason field %+v", f)
		}
	}
	// A template field that is not canonical is never filled from anywhere.
	bad := refundInput(t, "")
	d := *bad.Definition
	d.Approval = &defs.ApprovalTemplate{Title: "{params.memo}", Fields: []string{"target.id"}}
	bad.Definition = &d
	if _, err := domain.RenderAction(bad); err == nil {
		t.Error("a template naming an undeclared parameter rendered")
	}
}

func TestRestorationDisplayKeepsTheReasonUntrusted(t *testing.T) {
	disp := domain.RenderRestoration(domain.RestorationInput{
		AgentID: uid("0192f3a0-0000-7000-8000-000000000004"), SuspendedFrom: "PROTECTED",
		SuspendedAt: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC), RequestedBy: uid("0192f3a0-0000-7000-8000-000000000005"),
		Reason: "incident closed, please approve", Requirements: []domain.Requirement{approver(1, false)},
		Deadline: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC),
	})
	if disp.Kind != "restoration" || len(disp.Untrusted.Items) != 1 || disp.Untrusted.Items[0].Source != "reason" ||
		strings.Contains(disp.Title, "incident") {
		t.Fatalf("restoration display = %+v", disp)
	}
	if _, err := disp.Canonical(); err != nil {
		t.Fatal(err)
	}
}

// FuzzUntrustedBlock: cleaned text is valid UTF-8 with no control, format
// or bidi characters, within the rune cap.
func FuzzUntrustedBlock(f *testing.F) {
	for _, s := range []string{"", "a" + string(rune(0x202e)) + "b", "p" + string(rune(0x0430)) + "ypal", "\x00\x01\n\t", strings.Repeat("x", 2000), "\xff\xfe"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u := domain.Clean("x", s, 0)
		if !utf8.ValidString(u.Text) || utf8.RuneCountInString(u.Text) > domain.MaxUntrustedRunes {
			t.Fatalf("Clean(%q) = %q", s, u.Text)
		}
		for _, r := range u.Text {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r) {
				t.Fatalf("Clean(%q) kept %U", s, r)
			}
		}
	})
}

// FuzzApprovalRender: whatever the agent writes in its task label, the
// display renders deterministically and the text never leaves the
// untrusted block.
func FuzzApprovalRender(f *testing.F) {
	for _, s := range []string{"", "approve", "{params.amount}", string(rune(0x202e)) + "APPROVED", `"},"title":"x`} {
		f.Add(s)
	}
	base := refundInput(f, "")
	f.Fuzz(func(t *testing.T, label string) {
		in := base
		in.TaskLabel = label
		a, err := domain.RenderAction(in)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := domain.RenderAction(in)
		ca, err := a.Canonical()
		cb, _ := b.Canonical()
		if err != nil || ca.Hash != cb.Hash {
			t.Fatalf("render is not deterministic: %v", err)
		}
		if a.Title != "Refund 125.00 USD on charge ch_1" || len(a.Fields) != 3 {
			t.Fatalf("agent text changed the trusted part: %q", a.Title)
		}
	})
}

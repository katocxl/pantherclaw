// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"encoding/json/v2"
	"testing"

	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapping"
)

// TestHR681_StatementIsFixed: the Statement, word for word (G0 M28 D717).
// Covers: F960, HR-681, T-305
func TestHR681_StatementIsFixed(t *testing.T) {
	const want = "This map shows the PantherClaw controls mapped to each technique and the evidence for them. " +
		"A mapped control covers the technique, not every way of carrying it out. " +
		"Techniques outside PantherClaw need other tools. It is not a score or a guarantee."
	if domain.Statement != want {
		t.Fatalf("statement %q", domain.Statement)
	}
	if w := domain.BannedWord(domain.Statement); w != "" {
		t.Errorf("the statement alone reads as %q once removed", w)
	}
	if w := domain.BannedWord("Your agents are SAFE."); w != "SAFE" {
		t.Errorf("BannedWord missed SAFE: %q", w)
	}
	if w := domain.BannedWord("unsafe-looking words like safeguard"); w != "" {
		t.Errorf("not word-bounded: %q", w)
	}
}

// TestHR681_NoBannedWordInAnyThreatMapString: reason texts, fix labels,
// Why lines, Outside notes, Unaddressed reasons and a whole evaluated map
// carry none of the banned words (D717, D717a).
// Covers: F960, F962, HR-681, T-305
func TestHR681_NoBannedWordInAnyThreatMapString(t *testing.T) {
	check := func(where, s string) {
		t.Helper()
		if w := domain.BannedWord(s); w != "" {
			t.Errorf("%s: %q in %q", where, w, s)
		}
	}
	for _, r := range domain.Reasons() {
		if r.Text() == "" {
			t.Errorf("%s has no text", r)
		}
		check(string(r), r.Text())
	}
	check("sub-techniques", domain.SubtechniquesText(1, 2))
	for _, c := range mapping.Prevent {
		check(c.ID, c.Title)
		for id, w := range c.Why {
			check(c.ID+" "+id, w)
		}
	}
	for k, m := range mapping.Kinds {
		check(k, m.None)
		for id, w := range m.Why {
			check(k+" "+id, w)
		}
	}
	for _, o := range mapping.Outside {
		check(o.ID, o.Note)
	}
	for _, u := range mapping.Unaddressed {
		check(u.ID, u.Why)
	}
	// Every fix label and reason a fixture map yields, in its JSON.
	for _, in := range []domain.Inputs{business(), {EvaluatedAt: now}} {
		raw, err := json.Marshal(eval(in))
		if err != nil {
			t.Fatal(err)
		}
		check("evaluated map", string(raw))
	}
}

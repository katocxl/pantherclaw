// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
)

// TestHR636_KindsAndAttributesAreClosed: a kind keeps its named attributes
// only, an unknown kind keeps nothing, and a value a person could not be shown
// is dropped and counted.
// Covers: F924
func TestHR636_KindsAndAttributesAreClosed(t *testing.T) {
	kept, dropped := domain.Clean(domain.KindCustomGPT, map[string]string{
		"name": "x", "instructions": "be evil", "owner_email": "a@b", "visibility": "bad\u202evalue", "tool_kinds": strings.Repeat("a", 257),
	})
	if len(kept) != 1 || kept["name"] != "x" || dropped != 4 {
		t.Fatalf("kept %v dropped %d", kept, dropped)
	}
	if kept, dropped := domain.Clean("slack_bot", map[string]string{"name": "x"}); len(kept) != 0 || dropped != 1 {
		t.Fatalf("unknown kind: %v %d", kept, dropped)
	}
	for _, s := range domain.Sources {
		kind := domain.KindOf(s)
		names, ok := domain.Attributes(kind)
		if !ok || len(names) > 16 {
			t.Fatalf("%s: %v", kind, names)
		}
		for _, banned := range []string{"instructions", "prompt", "conversation", "message", "description", "content", "owner_email"} {
			if slices.Contains(names, banned) {
				t.Errorf("%s keeps %s", kind, banned)
			}
		}
		for _, k := range domain.MaterialKeys(kind) {
			if !slices.Contains(names, k) {
				t.Errorf("%s: material %s is not an attribute", kind, k)
			}
		}
	}
	if domain.KindOf("slack") != "" || domain.Reads("slack") != nil {
		t.Fatal("an unknown source has a kind")
	}
}

// TestHR637_AReportStartsUnread: a read is not scanned until it is read, a
// note takes the scanned mark away, and notes add up.
// Covers: F925
func TestHR637_AReportStartsUnread(t *testing.T) {
	r := domain.NewReport(domain.SourceCopilotStudio, "t")
	if r.Complete() || len(r.Scanned) != 0 {
		t.Fatalf("%+v", r)
	}
	r.Read(domain.ReadBots)
	r.Read(domain.ReadBotComponents)
	if !r.Complete() {
		t.Fatalf("%+v", r)
	}
	r.Note(domain.ReadBots, "one")
	r.Note(domain.ReadBots, "two")
	if r.Complete() || slices.Contains(r.Scanned, domain.ReadBots) || r.NotScanned[domain.ReadBots] != "one; two" {
		t.Fatalf("%+v", r)
	}
	f := r.Fields()
	if f["/not_scanned/bots"] != "one; two" || f["/scanned/bot_components"] != "true" {
		t.Fatalf("%v", f)
	}
	if !domain.KeepsPrior("skill_count", map[string]string{domain.ReadBotComponents: "x"}) ||
		domain.KeepsPrior("skill_count", nil) || domain.KeepsPrior("auth_mode", map[string]string{domain.ReadBotComponents: "x"}) {
		t.Fatal("KeepsPrior")
	}
}

// TestHR638_TextIsCutOnACharacter: Text keeps valid, plain, bounded text.
// Covers: F926
func TestHR638_TextIsCutOnACharacter(t *testing.T) {
	for _, in := range []string{strings.Repeat("é", 300), "a\x00b", "\xff\xfe", "line\nbreak", " x"} {
		if out := domain.Text(in); !domain.Plain(out) {
			t.Errorf("Text(%q) = %q", in, out)
		}
	}
	if domain.Text(" a\u200bb ") != "ab" {
		t.Fatal(domain.Text(" a\u200bb "))
	}
	if !domain.TenantOK("00000000-5a5a-4000-8000-00000000e001") || domain.TenantOK("") || domain.TenantOK("a b") || domain.TenantOK("-a") {
		t.Fatal("TenantOK")
	}
}

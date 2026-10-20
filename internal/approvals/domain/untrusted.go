// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// UntrustedLabel is the fixed label above every untrusted block (HR-034).
const UntrustedLabel = "Written by the agent or the requester. PantherClaw has not checked this text."

// Untrusted text bounds.
const (
	// MaxUntrustedRunes caps one item of the untrusted block.
	MaxUntrustedRunes = 1000
	// MaxUntrustedItems caps the items of one block.
	MaxUntrustedItems = 16
)

// Untrusted is one item of agent- or requester-supplied text, cleaned for
// display: never part of a template, a notification or a binding decision.
type Untrusted struct {
	// Source says where the text came from: "task_label", "param:<name>",
	// "attribute:<name>", "reason" or "evidence".
	Source string `json:"source"`
	Text   string `json:"text"`
	// MixedScript is set when a word mixes writing systems, a sign of a
	// look-alike (confusable) identifier (HR-102).
	MixedScript bool `json:"mixed_script,omitzero"`
	// Truncated is set when the text was cut to MaxUntrustedRunes.
	Truncated bool `json:"truncated,omitzero"`
}

// Clean returns s without control, format and bidi characters (newlines and
// tabs become spaces), cut to max runes, and whether a word in it mixes
// scripts (HR-034, HR-102).
func Clean(source, s string, maxRunes int) Untrusted {
	if maxRunes <= 0 {
		maxRunes = MaxUntrustedRunes
	}
	var b strings.Builder
	n := 0
	out := Untrusted{Source: source}
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			continue
		case r == '\n' || r == '\r' || r == '\t':
			r = ' '
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r) ||
			r == 0x2028 || r == 0x2029 || invisibleMark(r):
			continue
		}
		if n == maxRunes {
			out.Truncated = true
			break
		}
		b.WriteRune(r)
		n++
	}
	out.Text = b.String()
	out.MixedScript = MixedScript(out.Text)
	return out
}

// invisibleMark reports a mark that changes how text looks or compares
// without being seen: the variation selectors (U+FE00–FE0F and
// U+E0100–E01EF) and the combining grapheme joiner U+034F. The web
// console's UntrustedText removes the same set (G0 UI D64).
func invisibleMark(r rune) bool {
	return (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) || r == 0x034F
}

// scriptGroups are the writing systems a word may not mix. Han, Hiragana
// and Katakana together are Japanese, Han and Hangul Korean.
var scriptGroups = []struct {
	name   string
	tables []*unicode.RangeTable
}{
	{"latin", []*unicode.RangeTable{unicode.Latin}},
	{"cyrillic", []*unicode.RangeTable{unicode.Cyrillic}},
	{"greek", []*unicode.RangeTable{unicode.Greek}},
	{"armenian", []*unicode.RangeTable{unicode.Armenian}},
	{"georgian", []*unicode.RangeTable{unicode.Georgian}},
	{"cherokee", []*unicode.RangeTable{unicode.Cherokee}},
	{"hebrew", []*unicode.RangeTable{unicode.Hebrew}},
	{"arabic", []*unicode.RangeTable{unicode.Arabic}},
	{"cjk", []*unicode.RangeTable{unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul}},
}

func scriptOf(r rune) string {
	if unicode.Is(unicode.Common, r) || unicode.Is(unicode.Inherited, r) {
		return "" // digits, punctuation, marks and symbols shared by every script
	}
	for _, g := range scriptGroups {
		for _, t := range g.tables {
			if unicode.Is(t, r) {
				return g.name
			}
		}
	}
	if unicode.IsLetter(r) {
		return "other"
	}
	return ""
}

// MixedScript reports whether any word of s holds letters of two writing
// systems, such as "paypal" written with a Cyrillic "a".
func MixedScript(s string) bool {
	for _, w := range strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		seen := ""
		for _, r := range w {
			sc := scriptOf(r)
			if sc == "" {
				continue
			}
			if seen != "" && sc != seen {
				return true
			}
			seen = sc
		}
	}
	return false
}

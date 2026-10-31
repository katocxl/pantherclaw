// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/detection/injection"
)

// hiddenClass is why a character hides text.
type hiddenClass int

const (
	notHidden hiddenClass = iota
	hiddenZeroWidth
	hiddenBidi
	hiddenTag
)

// joiningScripts write words with zero-width joiners on purpose.
var joiningScripts = []*unicode.RangeTable{
	unicode.Arabic, unicode.Syriac, unicode.Mongolian, unicode.Devanagari, unicode.Bengali, unicode.Gurmukhi, unicode.Gujarati,
	unicode.Oriya, unicode.Tamil, unicode.Telugu, unicode.Kannada, unicode.Malayalam, unicode.Sinhala, unicode.Khmer,
	unicode.Myanmar, unicode.Tibetan,
}

// isRTL reports a letter of a right-to-left script, beside which the
// directional marks are ordinary punctuation.
func isRTL(r rune) bool {
	return unicode.In(r, unicode.Arabic, unicode.Hebrew, unicode.Syriac)
}

// isEmoji is a coarse test for the characters a zero-width joiner joins.
func isEmoji(r rune) bool {
	return r >= 0x1F000 && r <= 0x1FAFF || r >= 0x2190 && r <= 0x2BFF || r == 0xFE0F
}

// classify says whether the character at i (r, n bytes) hides text. Scripts
// and emoji that use these characters for what they are for stay out of it
// (D210: benign tools are not flagged).
func classify(s string, i int, r rune, n int) hiddenClass {
	prev, _ := utf8.DecodeLastRuneInString(s[:i])
	next, _ := utf8.DecodeRuneInString(s[i+n:])
	switch {
	case r >= 0xE0000 && r <= 0xE007F:
		if inFlagTag(s, i) {
			return notHidden
		}
		return hiddenTag
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return hiddenBidi
	case r == 0x200E, r == 0x200F, r == 0x061C:
		if isRTL(prev) || isRTL(next) {
			return notHidden
		}
		return hiddenBidi
	case r == 0x200C, r == 0x200D:
		if isEmoji(prev) && isEmoji(next) || unicode.In(prev, joiningScripts...) || unicode.In(next, joiningScripts...) {
			return notHidden
		}
		return hiddenZeroWidth
	case r == 0xFEFF:
		if i == 0 {
			return notHidden // a byte order mark
		}
		return hiddenZeroWidth
	case r >= 0xE0100 && r <= 0xE01EF:
		if unicode.Is(unicode.Han, prev) {
			return notHidden // an ideographic variation sequence
		}
		return hiddenZeroWidth
	case r == 0x00AD, r == 0x034F, r == 0x180E, r == 0x200B, r >= 0x2060 && r <= 0x2064, r >= 0x206A && r <= 0x206F,
		r >= 0xFFF9 && r <= 0xFFFB:
		return hiddenZeroWidth
	}
	return notHidden
}

// inFlagTag reports whether the tag character at i belongs to a subdivision
// flag: the black flag, at most six tag characters, and the cancel tag.
func inFlagTag(s string, i int) bool {
	start := i
	for n := 0; start > 0 && n <= 6; n++ {
		r, w := utf8.DecodeLastRuneInString(s[:start])
		if r == 0x1F3F4 {
			break
		}
		if r < 0xE0000 || r > 0xE007F {
			return false
		}
		start -= w
	}
	if r, _ := utf8.DecodeLastRuneInString(s[:start]); r != 0x1F3F4 {
		return false
	}
	end := i
	for n := 0; end < len(s) && n <= 6; n++ {
		r, w := utf8.DecodeRuneInString(s[end:])
		end += w
		if r == 0xE007F {
			return true
		}
		if r < 0xE0000 || r > 0xE007F {
			return false
		}
	}
	return false
}

// hiddenTally counts what one text hid.
type hiddenTally struct {
	zeroWidth, bidi, tag, comments int
	spans                          []Span
}

// scan adds what s hides, each hit's span from at(start, end).
func (h *hiddenTally) scan(s string, at func(start, end int) Span) {
	// A run of neighbouring characters is one span.
	runStart, runEnd := -1, -1
	flush := func() {
		if runStart >= 0 {
			h.spans = append(h.spans, at(runStart, runEnd))
			runStart = -1
		}
	}
	for i, r := range s {
		n := utf8.RuneLen(r)
		if r == utf8.RuneError {
			continue
		}
		switch classify(s, i, r, n) {
		case notHidden:
			continue
		case hiddenZeroWidth:
			h.zeroWidth++
		case hiddenBidi:
			h.bidi++
		case hiddenTag:
			h.tag++
		}
		if runStart >= 0 && runEnd == i {
			runEnd = i + n
			continue
		}
		flush()
		runStart, runEnd = i, i+n
	}
	flush()
	h.scanComments(s, at)
}

// scanComments adds each HTML comment with something in it; one that is never
// closed hides everything after it.
func (h *hiddenTally) scanComments(s string, at func(start, end int) Span) {
	for off := 0; ; {
		i := strings.Index(s[off:], "<!--")
		if i < 0 {
			return
		}
		start := off + i
		body := s[start+len("<!--"):]
		end := len(s)
		if j := strings.Index(body, "-->"); j >= 0 {
			body = body[:j]
			end = start + len("<!--") + j + len("-->")
		}
		if strings.TrimSpace(body) != "" {
			h.comments++
			h.spans = append(h.spans, at(start, end))
		}
		off = end
	}
}

// hidden is the hidden_instruction check: characters that do not show, and
// HTML comments, in the description or anywhere in the schema. Agents read
// these; people rarely do.
func hidden(t Tool, schema *node) *Flag {
	var h hiddenTally
	h.scan(t.Description, func(start, end int) Span { return Span{FieldDescription, start, end} })
	schema.eachString(func(s string, _ bool, n *node) {
		// One span per schema token: offsets inside it would not line up with
		// the JSON escapes of the listed text.
		h.scan(s, func(int, int) Span { return Span{FieldInputSchema, n.start, n.end} })
	})
	if h.zeroWidth+h.bidi+h.tag+h.comments == 0 {
		return nil
	}
	sev := SeverityMedium
	if h.tag+h.bidi > 0 {
		sev = SeverityHigh
	}
	return &Flag{
		Kind: KindHiddenInstruction, Severity: sev, Spans: capSpans(dedupe(h.spans)),
		Note: fmt.Sprintf("Text that does not show: %d zero-width, %d bidirectional and %d tag characters, %d HTML comments.",
			h.zeroWidth, h.bidi, h.tag, h.comments),
	}
}

// dedupe drops repeats of a span.
func dedupe(s []Span) []Span {
	seen := map[Span]bool{}
	out := make([]Span, 0, len(s))
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// schemaTextKeys hold machine strings, not text an agent reads as prose: a
// regular expression or a reference, where the patterns would misfire.
var schemaTextKeys = map[string]bool{"pattern": true, "$ref": true, "$schema": true, "$id": true, "format": true, "type": true}

// injected is the injection_pattern check: the injection package's patterns
// over the description and the schema's strings.
func injected(t Tool, schema *node) *Flag {
	var names []string
	var spans []Span
	seen := map[string]bool{}
	note := func(r injection.Result, span func(injection.Span) Span) {
		for i, p := range r.Patterns {
			spans = append(spans, span(r.Spans[i]))
			if !seen[p] {
				seen[p] = true
				names = append(names, p)
			}
		}
	}
	note(injection.Scan(t.Description), func(x injection.Span) Span { return Span{FieldDescription, x.Start, x.End} })
	schema.eachString(func(s string, isValue bool, n *node) {
		if isValue && !schemaTextKeys[n.key] {
			note(injection.Scan(s), func(injection.Span) Span { return Span{FieldInputSchema, n.start, n.end} })
		}
	})
	if len(names) == 0 {
		return nil
	}
	return &Flag{
		Kind: KindInjectionPattern, Severity: SeverityHigh, Spans: capSpans(dedupe(spans)),
		Note: "Instruction-like text, patterns: " + strings.Join(names, ", ") + ".",
	}
}

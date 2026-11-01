// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package offline

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"unicode"

	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/validate"
)

// Rendering bounds.
const (
	// MarkdownCap bounds a Markdown report (D122): it stays under what a
	// pull request comment takes.
	MarkdownCap = 60 << 10
	// maxFieldRunes bounds one rendered field.
	maxFieldRunes = 300
	// maxListed bounds each rendered list; JSON keeps everything.
	maxListed = 50
)

// JSON is the report as JSON.
func (r *Report) JSON() ([]byte, error) {
	b, err := json.Marshal(r, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// writer renders one report: heading and line differ per format, field
// makes one piece of file text safe for it.
type writer struct {
	lines   []string
	heading func(string) string
	item    string
	field   func(string) string
}

func (w *writer) line(format string, args ...any) {
	w.lines = append(w.lines, fmt.Sprintf(format, args...))
}

func (w *writer) title(s string) { w.lines = append(w.lines, w.heading(s)) }

// list renders at most maxListed rows and says how many it left out.
func list[T any](w *writer, rows []T, render func(T)) {
	for i, row := range rows {
		if i == maxListed {
			w.line("%s%d more; see --format json", w.item, len(rows)-maxListed)
			return
		}
		render(row)
	}
}

func (r *Report) render(w *writer) {
	f := w.field
	verdict := "passed"
	if !r.Passed {
		verdict = "FAILED"
	}
	w.title("PantherClaw policy check: " + verdict)
	if r.Policy != "" {
		w.line("%spolicy %s", w.item, f(r.Policy))
	}
	for _, reason := range r.Failures {
		w.line("%sfailed: %s", w.item, reason)
	}

	w.title("Validation")
	state := "passed"
	if !r.Validation.Passed {
		state = "failed"
	}
	w.line("%s, %d findings", state, len(r.Validation.Findings))
	list(w, r.Validation.Findings, func(x pdomain.Finding) {
		sampled := ""
		if x.SampleBased {
			sampled = ", sample-based"
		}
		w.line("%s%s %s%s: %s", w.item, f(x.Severity), f(x.Code), sampled, f(x.Detail))
	})
	w.line("%snot checked offline: %s", w.item, strings.Join(mapped(r.Validation.NotChecked, f), "; "))

	w.title("Scenarios")
	s := r.Scenarios
	passedCases := 0
	for _, c := range s.Cases {
		if c.Passed {
			passedCases++
		}
	}
	w.line("%d of %d cases passed; %d mutants, %d surviving", passedCases, len(s.Cases), s.Mutants, len(s.Surviving))
	if s.Error != "" {
		w.line("%snot run to the end: %s", w.item, f(s.Error))
	}
	list(w, failing(s.Cases), func(c pdomain.CaseResult) { w.line("%scase %s failed: %s", w.item, f(c.ID), f(c.Detail)) })
	list(w, s.Surviving, func(m pdomain.MutantResult) {
		w.line("%smutant survives on rule %s: %s", w.item, f(m.Rule), f(m.Mutation))
	})
	list(w, s.Uncompilable, func(m pdomain.MutantResult) {
		w.line("%smutant does not compile on rule %s: %s", w.item, f(m.Rule), f(m.Mutation))
	})
	list(w, s.Automations, func(a Automation) {
		state := "passed"
		if !a.Passed {
			state = "failed"
		}
		w.line("%sautomation %s %s, %d cases", w.item, f(a.File), state, len(a.Cases))
		for _, k := range a.Missing {
			w.line("%skind not covered: %s", w.item, f(k))
		}
		for _, c := range a.Cases {
			if !c.Passed {
				w.line("%scase %s failed: %s", w.item, f(c.Name), f(strings.Join(c.Differences, "; ")))
			}
		}
	})

	w.title("Rule changes")
	if r.Changes == nil {
		w.line("no base given: nothing compared")
	} else {
		c := r.Changes
		w.line("direction %s: %d looser, %d unknown, %d tighter, %d neutral", c.Direction, len(c.Looser), len(c.Unknown), len(c.Tighter), len(c.Neutral))
		for _, group := range [][]pdomain.Change{c.Looser, c.Unknown, c.Tighter, c.Neutral} {
			list(w, group, func(ch pdomain.Change) { w.line("%s%s: %s", w.item, ch.Direction, f(ch.Sentence)) })
		}
	}

	w.title("Outcome samples")
	switch o := r.Outcomes; {
	case o == nil:
		w.line("no base given: nothing sampled; %s", OutcomeLimit)
	case o.Error != "":
		w.line("0 sampled, %s; %s", f(o.Error), o.Limit)
	default:
		w.line("%d sampled, %d changed; %s", o.Sampled, len(o.Changes), o.Limit)
		if len(o.Changes) > 0 {
			w.line("%s%s", w.item, f(outcomeCounts(o)))
		}
		list(w, o.Changes, func(c validate.OutcomeChange) {
			w.line("%s%s %s: %s to %s", w.item, c.Category, f(c.Operation), c.BeforeDecision, c.AfterDecision)
		})
	}
}

// Text is the report as plain text, one report line per line. No file text
// can start a line, end one or carry a control sequence, so it cannot
// write a runner's workflow command (HR-565).
func (r *Report) Text() []byte {
	w := &writer{heading: func(s string) string { return s }, item: "  ", field: Plain}
	r.render(w)
	return []byte(strings.Join(w.lines, "\n") + "\n")
}

// Markdown is the report as Markdown, at most MarkdownCap bytes (D122).
func (r *Report) Markdown() []byte {
	w := &writer{heading: func(s string) string { return "### " + s }, item: "- ", field: Escape}
	r.render(w)
	const cut = "\n\nReport cut at 60 KiB; the JSON format has all of it.\n"
	var b bytes.Buffer
	for i, l := range w.lines {
		// Lines stay whole, so no code span is ever cut in half.
		if b.Len()+len(l)+len(cut)+1 > MarkdownCap {
			b.WriteString(cut)
			return b.Bytes()
		}
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(l)
	}
	b.WriteByte('\n')
	return b.Bytes()
}

func failing(cases []pdomain.CaseResult) []pdomain.CaseResult {
	return slices.DeleteFunc(slices.Clone(cases), func(c pdomain.CaseResult) bool { return c.Passed })
}

func mapped(in []string, f func(string) string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = f(s)
	}
	return out
}

// invisible reports a rune that must not reach a report: control, format
// and bidi characters and line separators.
func invisible(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r) ||
		unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)
}

// clean turns invisible runes into spaces and caps the field.
func clean(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.ToValidUTF8(s, string(unicode.ReplacementChar)) {
		if n == maxFieldRunes {
			b.WriteString("...")
			break
		}
		n++
		if invisible(r) {
			r = ' '
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Plain makes file text safe for a text report. The legacy runner command
// prefixes work anywhere in a line, so they are split.
func Plain(s string) string {
	s = clean(s)
	s = strings.ReplaceAll(s, "##[", "# #[")
	s = strings.ReplaceAll(s, "##vso[", "# #vso[")
	return s
}

// Escape puts file text in a code span, the one place GitHub and GitLab
// Markdown leave alone (D122, D131, HR-565): no markup, mention, issue or
// commit reference, emoji or link is read inside one. The span's fence is
// longer than any backtick run in the text, so the text cannot close it,
// and clean has taken out the line breaks that could end it.
func Escape(s string) string {
	s = clean(s)
	if s == "" {
		return ""
	}
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	pad := ""
	if s[0] == '`' || s[len(s)-1] == '`' {
		pad = " " // a backtick must not touch the fence
	}
	return fence + pad + s + pad + fence
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package injection scans tool descriptions for instruction-like content
// (G0 M10 D11, D47; PN-006.2, HR-244). Tool poisoning hides instructions to
// the agent where agents read them and people rarely do: in a tool's
// description. The scan runs on the description a gateway observed when a
// tool drifted, and on the reviewed descriptions when a package is
// imported. A hit is recorded as audit.connection.tool_description_flagged
// with the description's digest and a short excerpt, and the package
// version goes to TOOL_REVIEW. The scan only flags: quarantine on drift
// stays automatic (M6) and no detection lifts it.
package injection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// AuditName is the audit event a hit writes (the pc.tools.description_injection
// rule reads it).
const AuditName = "connection.tool_description_flagged"

// Scan outcomes recorded beside a drift report (D47).
const (
	ScanFlagged    = "flagged"
	ScanClean      = "clean"
	ScanNotScanned = "not_scanned"
	// ScanPartial is a clean scan of a description the gateway cut short: the
	// rest was not scanned, so it is never recorded as clean (D59 M8).
	ScanPartial = "partial"
)

// MaxExcerpt bounds the recorded excerpt, in bytes.
const MaxExcerpt = 512

// patterns are the instruction-like shapes the scan flags, by name.
var patterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"ignore_instructions", regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(the\s+|your\s+)?(previous|prior|above|earlier|preceding|other)\s+(instructions?|prompts?|messages?|rules?|directions?)`)},
	{"system_prompt", regexp.MustCompile(`(?i)(system\s+prompt|<\s*/?\s*system\s*>|\[\s*system\s*\]|\bdeveloper\s+message\b)`)},
	{"hidden_tag", regexp.MustCompile(`(?i)<\s*/?\s*(important|secret|hidden|instructions?|admin|override)\s*>`)},
	{"conceal_from_user", regexp.MustCompile(`(?i)\b(do\s+not|don't|never)\s+(tell|inform|mention|reveal|show|disclose)\b[^.]{0,40}\buser\b`)},
	{"read_secrets", regexp.MustCompile(`(?i)(~|\$home|%userprofile%)[/\\]\.(ssh|aws|gnupg|config|kube|docker)|\bid_(rsa|ed25519)\b|\.env\b|\bprivate[\s_-]+key\b|\bcredentials?\s+file\b`)},
	{"before_tool_use", regexp.MustCompile(`(?i)\b(before|after)\s+(using|calling|invoking|running)\s+(this|any|the|every)\s+(other\s+)?tools?\b`)},
	{"exfiltrate", regexp.MustCompile(`(?i)\bexfiltrat|\b(send|post|upload|forward)\s+(it|them|this|the\s+\w+|all\s+\w+)\s+to\s+(https?://|\S+@\S+)`)},
	{"role_override", regexp.MustCompile(`(?i)\byou\s+are\s+now\b|\bact\s+as\s+(an?\s+)?(admin|administrator|root|system|developer)\b`)},
}

// Result is what a scan found.
type Result struct {
	Flagged  bool
	Patterns []string
	// Excerpt is the text around the first hit, at most MaxExcerpt bytes,
	// with control characters removed.
	Excerpt string
	// ExcerptNormalized is the same span of the normalised text the patterns
	// matched (D74).
	ExcerptNormalized string
	// Digest is "sha256:<hex>" of the description.
	Digest string
}

// Scan checks one description.
func Scan(desc string) Result {
	sum := sha256.Sum256([]byte(desc))
	r := Result{Digest: "sha256:" + hex.EncodeToString(sum[:])}
	text, at := normalize(desc)
	first := -1
	for _, p := range patterns {
		loc := p.re.FindStringIndex(text)
		if loc == nil {
			continue
		}
		r.Patterns = append(r.Patterns, p.name)
		if first < 0 || loc[0] < first {
			first = loc[0]
		}
	}
	if len(r.Patterns) == 0 {
		return r
	}
	r.Flagged = true
	r.Excerpt = excerpt(desc, at[first])
	r.ExcerptNormalized = excerpt(text, first)
	return r
}

// excerpt returns up to MaxExcerpt bytes of clean text starting a little
// before at.
func excerpt(s string, at int) string {
	start := max(0, at-80)
	for start > 0 && !utf8.RuneStart(s[start]) {
		start--
	}
	var b strings.Builder
	for _, r := range s[start:] {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			r = ' '
		}
		if b.Len()+utf8.RuneLen(r) > MaxExcerpt {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// Record writes the audit event of a hit in tx: what was flagged (object),
// which tool, the description's digest, the patterns and the excerpt.
func Record(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, object audit.Object, tool, source string, r Result,
	extra map[string]string,
) error {
	details := map[string]string{
		"upstream_tool": tool, "description_digest": r.Digest, "patterns": strings.Join(r.Patterns, ","),
		"excerpt": r.Excerpt, "excerpt_normalized": r.ExcerptNormalized, "source": source,
	}
	for k, v := range extra {
		details[k] = v
	}
	for _, k := range []string{"excerpt", "excerpt_normalized"} {
		if details[k] == "" {
			delete(details, k)
		}
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: AuditName, Actor: actor, Outcome: audit.Success, ReasonCode: "TOOL_DESCRIPTION_FLAGGED", Object: &object,
		Details: details,
	})
	return err
}

// Normalize prepares a description for the scan (D59 M9): NFKC folds
// fullwidth and compatibility forms, format characters (zero-width and
// bidirectional controls) are dropped, every space separator becomes a
// plain space, and Cyrillic and Greek letters that look like Latin ones
// become those Latin letters, so look-alike spellings match the patterns.
func Normalize(s string) string {
	out, _ := normalize(s)
	return out
}

// normalize is Normalize applied one character at a time, with the offset
// in s of each byte of the result, so a hit maps back to the raw text (D74).
func normalize(s string) (string, []int) {
	var b strings.Builder
	b.Grow(len(s))
	at := make([]int, 0, len(s))
	for i, raw := range s {
		for _, r := range norm.NFKC.String(string(raw)) {
			switch {
			case unicode.Is(unicode.Cf, r):
				continue
			case unicode.IsSpace(r) || unicode.Is(unicode.Z, r):
				r = ' '
			}
			if l, ok := homoglyphs[r]; ok {
				r = l
			}
			b.WriteRune(r)
			for range utf8.RuneLen(r) {
				at = append(at, i)
			}
		}
	}
	return b.String(), at
}

// homoglyphs maps Cyrillic and Greek letters to the Latin letters they
// look like.
var homoglyphs = map[rune]rune{
	// Cyrillic.
	'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'з': '3', 'і': 'i', 'ї': 'i', 'ј': 'j', 'к': 'k', 'м': 'm', 'н': 'h',
	'о': 'o', 'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's', 'ԁ': 'd', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w',
	'һ': 'h', 'ь': 'b', 'А': 'A', 'В': 'B', 'Е': 'E', 'Ё': 'E', 'І': 'I', 'Ї': 'I', 'Ј': 'J', 'К': 'K', 'М': 'M',
	'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X', 'Ѕ': 'S', 'Ԁ': 'D', 'Ӏ': 'I', 'Ԛ': 'Q',
	'Ԝ': 'W', 'Һ': 'H',
	// Greek.
	'α': 'a', 'β': 'b', 'γ': 'y', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'σ': 'o', 'τ': 't',
	'υ': 'u', 'χ': 'x', 'ω': 'w', 'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M',
	'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
}

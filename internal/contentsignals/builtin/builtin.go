// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package builtin is the built-in content classifier (G0 M27 D503): pure Go
// regular expressions and an entropy measure, no model and no network. It
// knows listed phrases and formats, nothing else: paraphrased, split or
// re-encoded content passes, which is why nothing it returns is a safety
// claim (F789, F801). RE2 keeps every pattern linear in the bounded input.
//
// Findings name a kind and a location, never the value (HR-649). A location
// keeps a JSON member name only when the name is a plain word that nothing
// here flags, so a value used as a key does not leak through its location.
package builtin

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"errors"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/contentsignals/domain"
	"github.com/katocxl/pantherclaw/internal/contentsignals/ports"
)

const (
	// maxStrings caps the JSON strings looked at; more is an error, which
	// the caller makes a scan_incomplete.
	maxStrings = 4096
	// entropyMin is the least bits per character of a high-entropy token.
	// Hex tops out at 4, so a digest or a commit id never reaches it.
	entropyMin = 4.5
	// tokenMax is the most of a token measured.
	tokenMax = 512
)

// ErrTooManyStrings: the body holds more strings than are looked at.
var ErrTooManyStrings = errors.New("builtin: too many strings")

type pattern struct {
	kind string
	re   *regexp.Regexp
}

var patterns = []pattern{
	{domain.KindInjectionPhrase, regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|your\s+|my\s+)?(?:previous|prior|above|earlier|preceding|system)\s+(?:instructions?|prompts?|messages?|rules?|directions?)`)},
	{domain.KindInjectionPhrase, regexp.MustCompile(`(?i)\b(?:reveal|show|print|repeat|output)\s+(?:me\s+)?(?:your\s+|the\s+)(?:system\s+prompt|hidden\s+instructions?|initial\s+instructions?)`)},
	{domain.KindInjectionPhrase, regexp.MustCompile(`(?i)\byou\s+are\s+now\s+(?:in\s+)?(?:developer\s+mode|dan\b|jailbroken|unrestricted)`)},
	{domain.KindInjectionPhrase, regexp.MustCompile(`(?i)(?:^|\n)\s*(?:new|updated|important)\s+(?:system\s+)?instructions?\s*:`)},
	{domain.KindInjectionPhrase, regexp.MustCompile(`<\|im_start\|>|<\|system\|>|\[/?INST\]|<<SYS>>`)},
	{domain.KindSecretFormat, regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}`)},
	{domain.KindSecretFormat, regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{domain.KindSecretFormat, regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`)},
	{domain.KindSecretFormat, regexp.MustCompile(`xox[abposr]-[A-Za-z0-9-]{10,}`)},
	{domain.KindSecretFormat, regexp.MustCompile(`pc[kidrsebgl]_[A-Za-z0-9_]{20,}`)},
	{domain.KindPIIEmail, regexp.MustCompile(`[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}`)},
	{domain.KindPIINationalID, regexp.MustCompile(`\b(?:00[1-9]|0[1-9][0-9]|[1-5][0-9]{2}|6[0-57-9][0-9]|66[0-57-9]|[78][0-9]{2})-(?:0[1-9]|[1-9][0-9])-(?:000[1-9]|00[1-9][0-9]|0[1-9][0-9]{2}|[1-9][0-9]{3})\b`)},
}

var (
	cardRe = regexp.MustCompile(`\b[0-9](?:[ -]?[0-9]){12,18}\b`)
	// tokenRe finds tokens of 32 characters or more, the shortest measured.
	tokenRe = regexp.MustCompile(`[A-Za-z0-9+/_=-]{32,}`)
	plainRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,24}$`)
	indexRe = regexp.MustCompile(`^[0-9]{1,6}$`)
	wordRe  = regexp.MustCompile(`[A-Za-z]`)
)

// Classifier is the built-in classifier.
type Classifier struct{}

var _ ports.ContentClassifier = Classifier{}

// Classify implements ports.ContentClassifier: a JSON body string by string,
// anything else, or JSON that breaks part way, as text.
func (Classifier) Classify(ctx context.Context, in ports.Input) ([]domain.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	base := in.Location
	if !plainRe.MatchString(base) {
		base = "body"
	}
	if events, ok := sseData(in.Content); ok {
		return classifyEvents(base, events)
	}
	var found []domain.Finding
	finished, err := walk(in.Content, func(pointer, text string) {
		for _, k := range Kinds(text) {
			found = append(found, domain.Finding{Kind: k, Location: location(base, pointer)})
		}
	})
	if err != nil {
		return domain.Pick(found), err
	}
	if !finished {
		for _, k := range Kinds(string(in.Content)) {
			found = append(found, domain.Finding{Kind: k, Location: base})
		}
	}
	return domain.Pick(found), nil
}

// walk calls see with every string of a JSON text and reports whether the
// text was JSON read to its end.
func walk(raw []byte, see func(pointer, text string)) (bool, error) {
	if t := bytes.TrimLeft(raw, " \t\r\n"); len(t) == 0 || (t[0] != '{' && t[0] != '[' && t[0] != '"') {
		return false, nil
	}
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	n := 0
	for {
		tok, err := dec.ReadToken()
		if err != nil {
			return errors.Is(err, io.EOF), nil // broken JSON is scanned as text
		}
		if tok.Kind() != '"' {
			continue
		}
		if n++; n > maxStrings {
			return false, ErrTooManyStrings
		}
		see(string(dec.StackPointer()), tok.String())
	}
}

// Kinds lists the kinds flagged in text, each once.
func Kinds(text string) []string {
	var out []string
	add := func(k string) {
		for _, have := range out {
			if have == k {
				return
			}
		}
		out = append(out, k)
	}
	for _, p := range patterns {
		if p.re.MatchString(text) {
			add(p.kind)
		}
	}
	for _, m := range cardRe.FindAllString(text, -1) {
		if luhn(m) {
			add(domain.KindPIICard)
			break
		}
	}
	for _, t := range tokenRe.FindAllString(text, -1) {
		if Entropy(t[:min(len(t), tokenMax)]) >= entropyMin {
			add(domain.KindHighEntropy)
			break
		}
	}
	return out
}

// location is base and the pointer, each member name kept only when it says
// nothing of a value, within the bound.
func location(base, pointer string) string {
	var b strings.Builder
	b.WriteString(base)
	for seg := range strings.SplitSeq(strings.TrimPrefix(pointer, "/"), "/") {
		if seg == "" {
			continue
		}
		if !keep(seg) {
			seg = "*"
		}
		if b.Len()+1+len(seg) > domain.MaxLocation {
			break
		}
		b.WriteByte('/')
		b.WriteString(seg)
	}
	return b.String()
}

func keep(seg string) bool {
	if indexRe.MatchString(seg) {
		return true
	}
	return plainRe.MatchString(seg) && wordRe.MatchString(seg) && len(Kinds(seg)) == 0 && !cardRe.MatchString(seg)
}

// luhn reports whether the digits of s pass the Luhn check.
func luhn(s string) bool {
	sum, n := 0, 0
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		d := int(c - '0')
		if n%2 == 1 {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		n++
	}
	return n >= 13 && n <= 19 && sum%10 == 0
}

// Entropy is the Shannon entropy of s in bits per byte.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	e, n := 0.0, float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

// PlainLocation reports whether loc is base, or base followed by segments the
// built-in itself would keep: indices, "*" and plain-word member names that
// say nothing of a value (D533). A classifier's location must be one.
func PlainLocation(base, loc string) bool {
	if loc == base {
		return true
	}
	rest, ok := strings.CutPrefix(loc, base+"/")
	if !ok || len(loc) > domain.MaxLocation {
		return false
	}
	for seg := range strings.SplitSeq(rest, "/") {
		if seg != "*" && !keep(seg) {
			return false
		}
	}
	return true
}

// sseData un-frames a server-sent events body, as an MCP server may answer
// (D533): the data of each event, its data lines joined. ok is false for a
// body that is not one, which is read as it is.
func sseData(raw []byte) ([][]byte, bool) {
	t := bytes.TrimLeft(raw, " \t\r\n")
	if !bytes.HasPrefix(t, []byte("event:")) && !bytes.HasPrefix(t, []byte("data:")) &&
		!bytes.HasPrefix(t, []byte("id:")) && !bytes.HasPrefix(t, []byte(":")) {
		return nil, false
	}
	var events [][]byte
	var cur []byte
	have := false
	flush := func() {
		if have {
			events = append(events, cur)
		}
		cur, have = nil, false
	}
	for line := range bytes.SplitSeq(raw, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			flush()
			continue
		}
		data, ok := bytes.CutPrefix(line, []byte("data:"))
		if !ok {
			continue
		}
		data = bytes.TrimPrefix(data, []byte(" "))
		if have {
			cur = append(cur, '\n')
		}
		cur, have = append(cur, data...), true
	}
	flush()
	return events, true
}

// classifyEvents walks each event's data as JSON, under its index, and reads
// what is not JSON as text.
func classifyEvents(base string, events [][]byte) ([]domain.Finding, error) {
	var found []domain.Finding
	for i, data := range events {
		prefix := "/" + strconv.Itoa(i)
		finished, err := walk(data, func(pointer, text string) {
			for _, k := range Kinds(text) {
				found = append(found, domain.Finding{Kind: k, Location: location(base, prefix+pointer)})
			}
		})
		if err != nil {
			return domain.Pick(found), err
		}
		if !finished {
			for _, k := range Kinds(string(data)) {
				found = append(found, domain.Finding{Kind: k, Location: location(base, prefix)})
			}
		}
	}
	return domain.Pick(found), nil
}

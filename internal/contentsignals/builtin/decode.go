// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package builtin

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/katocxl/pantherclaw/internal/contentsignals/domain"
)

// Decoding before matching (G0 M30 D920, D921; HR-703). Every string the
// classifier looks at is also read through a few fixed layers, stacked at
// most decodeDepth deep, and each layer's output is matched against the
// injection phrases and secret formats (not PII, not entropy). It reads what
// those layers undo and nothing else: another encoding, a split or a
// paraphrase still passes. Decoding stops at a byte budget per scan, and a
// scan that stopped says so with decode_bound.

// decodeDepth is the most layers stacked on one string.
const decodeDepth = 3

// Layer names, as a finding's Encoding lists them.
const (
	layerZeroWidth  = "zero_width"
	layerConfusable = "confusable"
	layerEscape     = "escape"
	layerURL        = "url"
	layerEntity     = "entity"
	layerBase64     = "base64"
	layerHex        = "hex"
)

type layer struct {
	name string
	// apply returns what the layer reads in s: one rewrite of s, or each
	// encoded run in it decoded.
	apply func(s string) []string
}

var layers = []layer{
	{layerZeroWidth, one(stripInvisible)},
	{layerConfusable, one(foldConfusables)},
	{layerEscape, one(unescapeBackslash)},
	{layerURL, one(unescapePercent)},
	{layerEntity, one(unescapeEntities)},
	{layerBase64, decodeBase64Runs},
	{layerHex, decodeHexRuns},
}

func one(f func(string) string) func(string) []string {
	return func(s string) []string { return []string{f(s)} }
}

// decoder carries one scan's budget: the bytes all candidates may add up to.
type decoder struct {
	left int
	over bool
}

func newDecoder() *decoder { return &decoder{left: domain.MaxBody} }

// candidate is a string read through layers, named in application order.
type candidate struct {
	text string
	enc  string
}

// candidates lists what the layers read in s, each at most decodeDepth deep.
// A candidate equal to its input is dropped. Past the budget it stops and
// the decoder is over.
func (d *decoder) candidates(s string) []candidate {
	var out []candidate
	d.expand(s, nil, &out)
	return out
}

func (d *decoder) expand(s string, path []string, out *[]candidate) {
	if len(path) >= decodeDepth {
		return
	}
	for _, l := range layers {
		for _, t := range l.apply(s) {
			if d.over {
				return
			}
			if t == s || t == "" {
				continue
			}
			if len(t) > d.left {
				d.over = true
				return
			}
			d.left -= len(t)
			next := slices.Concat(path, []string{l.name})
			*out = append(*out, candidate{text: t, enc: encoding(next)})
			d.expand(t, next, out)
		}
	}
}

// encoding joins layer names within domain.MaxEncoding.
func encoding(path []string) string {
	e := strings.Join(path, "+")
	if len(e) > domain.MaxEncoding {
		e = e[:domain.MaxEncoding]
	}
	return e
}

// decodedKinds lists the kinds a decoded candidate is matched for: the
// injection phrases and secret formats only (D921).
func decodedKinds(text string) []string {
	var out []string
	for _, p := range patterns {
		if p.kind != domain.KindInjectionPhrase && p.kind != domain.KindSecretFormat {
			continue
		}
		if p.re.MatchString(text) && !contains(out, p.kind) {
			out = append(out, p.kind)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, have := range list {
		if have == s {
			return true
		}
	}
	return false
}

// findings matches every candidate of text and names each hit at loc with
// its layers. A kind text already shows plainly is not repeated.
func (d *decoder) findings(loc, text string, plain []string) []domain.Finding {
	var out []domain.Finding
	for _, c := range d.candidates(text) {
		for _, k := range decodedKinds(c.text) {
			if contains(plain, k) {
				continue
			}
			out = append(out, domain.Finding{Kind: k, Location: loc, Encoding: c.enc})
		}
	}
	return out
}

// stripInvisible removes zero-width and bidirectional controls.
func stripInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2060 && r <= 0x2064, r == 0xFEFF:
			return -1
		}
		return r
	}, s)
}

// confusables folds Cyrillic and Greek letters that look Latin onto Latin.
// The table is fixed and short; it is not Unicode's confusables list.
var confusables = map[rune]rune{
	// Cyrillic lower case.
	0x0430: 'a', 0x0432: 'b', 0x0435: 'e', 0x043E: 'o', 0x0440: 'p', 0x0441: 'c', 0x0443: 'y', 0x0445: 'x',
	0x0456: 'i', 0x0458: 'j', 0x0455: 's', 0x04BB: 'h', 0x0501: 'd', 0x051B: 'q', 0x051D: 'w',
	// Cyrillic upper case.
	0x0410: 'A', 0x0412: 'B', 0x0415: 'E', 0x041A: 'K', 0x041C: 'M', 0x041D: 'H', 0x041E: 'O', 0x0420: 'P',
	0x0421: 'C', 0x0422: 'T', 0x0425: 'X', 0x0423: 'Y', 0x0406: 'I', 0x0408: 'J', 0x0405: 'S',
	// Greek lower case.
	0x03B1: 'a', 0x03BF: 'o', 0x03BD: 'v', 0x03C1: 'p', 0x03B9: 'i', 0x03BA: 'k', 0x03C5: 'u',
	// Greek upper case.
	0x0391: 'A', 0x0392: 'B', 0x0395: 'E', 0x0396: 'Z', 0x0397: 'H', 0x0399: 'I', 0x039A: 'K', 0x039C: 'M',
	0x039D: 'N', 0x039F: 'O', 0x03A1: 'P', 0x03A4: 'T', 0x03A5: 'Y', 0x03A7: 'X',
}

// foldConfusables applies NFKC, then the fold table.
func foldConfusables(s string) string {
	return strings.Map(func(r rune) rune {
		if l, ok := confusables[r]; ok {
			return l
		}
		return r
	}, norm.NFKC.String(s))
}

var (
	backslashRe = regexp.MustCompile(`\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}`)
	percentRe   = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
	entityRe    = regexp.MustCompile(`&#[0-9]{1,7};|&#[xX][0-9A-Fa-f]{1,6};|&(?:lt|gt|amp|quot|apos);`)
	base64Re    = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	hexRe       = regexp.MustCompile(`[0-9A-Fa-f]{16,}`)
)

// unescapeBackslash reads \uXXXX and \xXX escapes.
func unescapeBackslash(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	out := backslashRe.ReplaceAllStringFunc(s, func(m string) string {
		if m[1] == 'x' {
			v, err := strconv.ParseUint(m[2:], 16, 8)
			if err != nil {
				return m
			}
			return string([]byte{uint8(v)})
		}
		v, err := strconv.ParseInt(m[2:], 16, 32)
		if err != nil {
			return m
		}
		return string(rune(v))
	})
	return strings.ToValidUTF8(out, string(utf8.RuneError))
}

// unescapePercent reads %XX escapes.
func unescapePercent(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	out := percentRe.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[1:], 16, 8)
		if err != nil {
			return m
		}
		return string([]byte{byte(v)})
	})
	return strings.ToValidUTF8(out, string(utf8.RuneError))
}

var namedEntities = map[string]string{"&lt;": "<", "&gt;": ">", "&amp;": "&", "&quot;": `"`, "&apos;": "'"}

// unescapeEntities reads HTML numeric entities and the five named ones.
func unescapeEntities(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	return entityRe.ReplaceAllStringFunc(s, func(m string) string {
		if v, ok := namedEntities[m]; ok {
			return v
		}
		digits, base := m[2:len(m)-1], 10
		if digits[0] == 'x' || digits[0] == 'X' {
			digits, base = digits[1:], 16
		}
		v, err := strconv.ParseUint(digits, base, 32)
		if err != nil || v > unicode.MaxRune {
			return m
		}
		return string(rune(v))
	})
}

// minRun is the fewest characters a base64 or hex run is read from.
const minRun = 16

// decodeBase64Runs decodes every run in s that reads as base64 (standard or
// URL alphabet, padding optional) into mostly printable text. A run that
// mixes the two alphabets is split at the other alphabet's characters, and
// each run is also read from offsets 1..3 and cut to whole quanta, so one
// character glued to either end does not hide it (G0 M30 D1215). Every
// reading is a candidate, charged to the scan's budget.
func decodeBase64Runs(s string) []string {
	var out []string
	add := func(enc *base64.Encoding, r string) {
		b, err := enc.DecodeString(r)
		if t, ok := readable(b); err == nil && ok && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	for _, run := range base64Re.FindAllString(s, -1) {
		run = strings.TrimRight(run, "=")
		var pieces []piece64
		switch std, url := strings.ContainsAny(run, "+/"), strings.ContainsAny(run, "-_"); {
		case std && url:
			for _, p := range strings.FieldsFunc(run, func(r rune) bool { return r == '-' || r == '_' }) {
				pieces = append(pieces, piece64{base64.RawStdEncoding, p})
			}
			for _, p := range strings.FieldsFunc(run, func(r rune) bool { return r == '+' || r == '/' }) {
				pieces = append(pieces, piece64{base64.RawURLEncoding, p})
			}
		case url:
			pieces = []piece64{{base64.RawURLEncoding, run}}
		default:
			pieces = []piece64{{base64.RawStdEncoding, run}}
		}
		for _, p := range pieces {
			for off := 0; off < 4 && len(p.run)-off >= minRun; off++ {
				r := p.run[off:]
				if len(r)%4 != 1 {
					add(p.enc, r)
				}
				if whole := r[:len(r)-len(r)%4]; whole != r {
					add(p.enc, whole)
				}
			}
		}
	}
	return out
}

// piece64 is a base64 run in one alphabet.
type piece64 struct {
	enc *base64.Encoding
	run string
}

// decodeHexRuns decodes every run of 16 or more hex digits into mostly
// printable text; a run of odd length is read without its first and
// without its last digit (G0 M30 D1215).
func decodeHexRuns(s string) []string {
	var out []string
	for _, run := range hexRe.FindAllString(s, -1) {
		reads := []string{run}
		if len(run)%2 != 0 {
			reads = []string{run[1:], run[:len(run)-1]}
		}
		for _, r := range reads {
			b, err := hex.DecodeString(r)
			if t, ok := readable(b); err == nil && ok && !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
	}
	return out
}

// readable is b as text, each byte that is not UTF-8 replaced with U+FFFD,
// and whether at least 80% of it is printable runes, an invalid byte
// counting as one unprintable rune. A few junk bytes from a glued prefix
// or suffix thus do not hide the text after them (G0 M30 D1215a).
func readable(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	n, ok := 0, 0
	for rest := b; len(rest) > 0; {
		r, size := utf8.DecodeRune(rest)
		rest = rest[size:]
		n++
		if r == utf8.RuneError && size == 1 {
			continue
		}
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			ok++
		}
	}
	return strings.ToValidUTF8(string(b), string(utf8.RuneError)), ok*5 >= n*4
}

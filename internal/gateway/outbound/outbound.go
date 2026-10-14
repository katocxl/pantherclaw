// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package outbound is the gateway's outbound credential check (HR-225, G0
// M12 D8): before an action is dispatched, its effective request is scanned
// for a secret the gateway holds in custody (refused) and for the shape of
// a known credential format (reported as findings, which a person must then
// approve). The check only ever adds requirements, and it never fails open:
// when it cannot look at everything (too many strings, a base64 value too
// large to decode) it says so with a scan_incomplete finding. It knows held
// secrets and listed formats, nothing else: a secret that is split,
// re-encoded another way than one base64 level, or paraphrased passes
// (R-24).
//
// Findings name a kind and a location, never the value.
package outbound

import (
	"bytes"
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// MinSecret is the shortest held secret that is matched; shorter values
// would match ordinary text.
const MinSecret = 8

// MaxFindings caps the findings of one action.
const MaxFindings = 16

// KindScanIncomplete is the finding of a scan that stopped before it had
// looked at everything; its location says where.
const KindScanIncomplete = "scan_incomplete"

const (
	// MaxParts caps the strings scanned for one action.
	MaxParts = 4096
	// MaxDecoded caps one base64 value's decoded size, and MaxDecodedTotal
	// all of an action's.
	MaxDecoded      = 1 << 20
	MaxDecodedTotal = 8 << 20
	minBase64       = 16
)

// Finding is one credential-shaped value: its format and where it is.
type Finding struct {
	Kind     string
	Location string
}

// Input is the effective request of one action. Every field is optional.
type Input struct {
	// Body is a raw request body; when it is JSON its string values are
	// scanned too, at body:<RFC 6901 pointer>.
	Body []byte
	// Query is the request query (query:<name>).
	Query url.Values
	// Path is the request path (path).
	Path string
	// Header holds the headers that are not injected by the gateway
	// (header:<name>).
	Header http.Header
	// Args are tool arguments as a JSON object (MCP, SDK, hook): arg:<key>
	// or arg:<key>/<pointer>.
	Args []byte
}

// Result is the outcome of a scan.
type Result struct {
	// HeldSecret: a secret the gateway holds is in the request. The
	// action is refused.
	HeldSecret bool
	// Findings are the known formats seen, and scan_incomplete when the scan
	// stopped early: one per kind first, then by location, at most
	// MaxFindings, sorted; empty when HeldSecret is set.
	Findings []Finding
}

type format struct {
	kind string
	re   *regexp.Regexp
}

// formats are the known credential formats (RE2 only). pantherclaw_token
// covers every PantherClaw secret credential prefix (ADR-0016: pck, pci,
// pcd, pcr, pcs, pce, pcb, pcl, pcg).
var formats = []format{
	{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`)},
	{"github_token", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`)},
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"aws_access_key", regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`)},
	{"slack_token", regexp.MustCompile(`xox[abposr]-[A-Za-z0-9-]{10,}`)},
	{"pantherclaw_token", regexp.MustCompile(`pc[kidrsebgl]_[A-Za-z0-9_]{20,}`)},
}

// part is a string to look at. heldOnly parts are searched for held secrets
// but not for formats (a whole body whose values are scanned one by one).
type part struct {
	location, text string
	heldOnly       bool
}

// Scan checks one action's request against the held secrets.
func Scan(in Input, held [][]byte) Result {
	c := collect(in)
	needles := needles(held)
	for _, p := range c.parts {
		for _, n := range needles {
			if strings.Contains(p.text, n) {
				return Result{HeldSecret: true}
			}
		}
	}
	seen := map[Finding]bool{}
	var all []Finding
	add := func(f Finding) {
		if !seen[f] {
			seen[f] = true
			all = append(all, f)
		}
	}
	for _, p := range c.parts {
		if p.heldOnly {
			continue
		}
		for _, f := range formats {
			if f.re.MatchString(p.text) {
				add(Finding{f.kind, p.location})
			}
		}
	}
	if c.incompleteAt != "" {
		add(Finding{KindScanIncomplete, c.incompleteAt})
	}
	return Result{Findings: pick(all)}
}

// pick keeps at most MaxFindings: the first location of every kind, so a
// private key never hides behind sixteen tokens, then the rest by location.
func pick(all []Finding) []Finding {
	sort.Slice(all, func(i, j int) bool {
		if all[i].Kind != all[j].Kind {
			return all[i].Kind < all[j].Kind
		}
		return all[i].Location < all[j].Location
	})
	if len(all) <= MaxFindings {
		return all
	}
	var first, rest []Finding
	for i, f := range all {
		if i == 0 || all[i-1].Kind != f.Kind {
			first = append(first, f)
		} else {
			rest = append(rest, f)
		}
	}
	sort.SliceStable(rest, func(i, j int) bool { return rest[i].Location < rest[j].Location })
	out := append(first, rest...)[:MaxFindings]
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Location < out[j].Location
	})
	return out
}

// needles returns every form of every long-enough held secret.
func needles(held [][]byte) []string {
	var out []string
	for _, s := range held {
		if len(s) < MinSecret {
			continue
		}
		forms := []string{
			string(s),
			base64.StdEncoding.EncodeToString(s),
			base64.RawStdEncoding.EncodeToString(s),
			base64.URLEncoding.EncodeToString(s),
			base64.RawURLEncoding.EncodeToString(s),
			url.QueryEscape(string(s)),
			url.PathEscape(string(s)),
		}
		seen := map[string]bool{}
		for _, f := range forms {
			if f != "" && !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	return out
}

// collector gathers the strings of a request, within the caps.
type collector struct {
	parts []part
	// n counts the strings that are not whole-body copies.
	n int
	// decoded is the decoded size so far.
	decoded int
	// incompleteAt is where the scan stopped, when it did.
	incompleteAt string
}

// add adds a string; it reports false, and records where, once the cap is
// reached.
func (c *collector) add(loc, text string) bool {
	if text == "" {
		return true
	}
	if c.n >= MaxParts {
		c.stopAt(loc)
		return false
	}
	c.n++
	c.parts = append(c.parts, part{location: loc, text: text})
	c.base64(loc, text)
	return true
}

// base64 adds the bytes a base64 value holds, one level deep (the content
// of a GitHub contents-API write). Binary content is scanned too: the
// patterns are ASCII, so a token wrapped in other bytes is still found.
func (c *collector) base64(loc, s string) {
	if len(s) < minBase64 || !alphabet(s) {
		return
	}
	if base64.StdEncoding.DecodedLen(len(s)) > MaxDecoded+3 {
		c.stopAt(loc + "(base64)")
		return
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(s)
		if err != nil {
			continue
		}
		if len(b) > MaxDecoded || c.decoded+len(b) > MaxDecodedTotal {
			c.stopAt(loc + "(base64)")
			return
		}
		c.decoded += len(b)
		c.parts = append(c.parts, part{location: loc + "(base64)", text: string(b)})
		return
	}
}

// stopAt records where the scan could not look.
func (c *collector) stopAt(loc string) {
	if c.incompleteAt == "" {
		c.incompleteAt = loc
	}
}

// alphabet reports whether s uses only base64 characters (either alphabet,
// padding included).
func alphabet(s string) bool {
	for i := 0; i < len(s); i++ {
		switch ch := s[i]; {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '+', ch == '/', ch == '-', ch == '_', ch == '=':
		default:
			return false
		}
	}
	return true
}

func collect(in Input) *collector {
	c := &collector{}
	if len(in.Body) > 0 {
		valid := c.json("body:", in.Body)
		c.parts = append(c.parts, part{location: "body", text: string(in.Body), heldOnly: valid})
	}
	for _, k := range slices.Sorted(mapKeys(in.Query)) {
		c.add("query:"+k, k)
		for _, v := range in.Query[k] {
			c.add("query:"+k, v)
		}
	}
	c.add("path", in.Path)
	if p, err := url.PathUnescape(in.Path); err == nil && p != in.Path {
		c.add("path", p)
	}
	for _, k := range slices.Sorted(mapKeys(in.Header)) {
		for _, v := range in.Header[k] {
			c.add("header:"+http.CanonicalHeaderKey(k), v)
		}
	}
	if len(in.Args) > 0 {
		valid := c.json("arg:", in.Args)
		c.parts = append(c.parts, part{location: "arg", text: string(in.Args), heldOnly: valid})
	}
	return c
}

func mapKeys[M ~map[string]V, V any](m M) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// json adds the string values (and member names) of a JSON text at
// prefix+pointer; for arguments the leading "/" is dropped: arg:content,
// arg:files/0/content. It reports whether the text was valid JSON that was
// read to its end; otherwise the caller scans the raw text for formats too,
// so a document that breaks halfway is not half unread.
func (c *collector) json(prefix string, raw []byte) bool {
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.ReadToken()
		if err != nil {
			return errors.Is(err, io.EOF) && c.incompleteAt == ""
		}
		if tok.Kind() != '"' {
			continue
		}
		ptr := string(dec.StackPointer())
		if prefix == "arg:" {
			ptr = strings.TrimPrefix(ptr, "/")
		}
		if !c.add(prefix+ptr, tok.String()) {
			return false
		}
	}
}

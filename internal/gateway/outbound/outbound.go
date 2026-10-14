// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package outbound is the gateway's outbound credential check (HR-225, G0
// M12 D8): before an action is dispatched, its effective request is scanned
// for a secret the gateway holds in custody (refused) and for the shape of
// a known credential format (reported as findings, which a person must then
// approve). The check only ever adds requirements. It knows held secrets
// and listed formats, nothing else: a secret that is split, re-encoded
// another way or paraphrased passes (R-24).
//
// Findings name a kind and a location, never the value.
package outbound

import (
	"bytes"
	"encoding/base64"
	"encoding/json/jsontext"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// MinSecret is the shortest held secret that is matched; shorter values
// would match ordinary text.
const MinSecret = 8

// MaxFindings caps the findings of one action.
const MaxFindings = 16

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
	// Findings are the known formats seen, deduplicated, sorted and
	// capped; empty when HeldSecret is set.
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

type part struct{ location, text string }

// Scan checks one action's request against the held secrets.
func Scan(in Input, held [][]byte) Result {
	parts := collect(in)
	needles := needles(held)
	for _, p := range parts {
		for _, n := range needles {
			if strings.Contains(p.text, n) {
				return Result{HeldSecret: true}
			}
		}
	}
	seen := map[Finding]bool{}
	var out []Finding
	jsonBody := false
	for _, p := range parts {
		jsonBody = jsonBody || strings.HasPrefix(p.location, "body:")
	}
	for _, p := range parts {
		if p.location == "body" && jsonBody {
			continue // its string values are scanned at their own locations
		}
		for _, f := range formats {
			if f.re.MatchString(p.text) {
				fd := Finding{f.kind, p.location}
				if !seen[fd] {
					seen[fd] = true
					out = append(out, fd)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Location < out[j].Location
	})
	if len(out) > MaxFindings {
		out = out[:MaxFindings]
	}
	return Result{Findings: out}
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

func collect(in Input) []part {
	var ps []part
	add := func(loc, text string) {
		if text != "" {
			ps = append(ps, part{loc, text})
		}
	}
	if len(in.Body) > 0 {
		add("body", string(in.Body))
		ps = append(ps, jsonParts("body:", in.Body)...)
	}
	for k, vs := range in.Query {
		add("query:"+k, k)
		for _, v := range vs {
			add("query:"+k, v)
		}
	}
	add("path", in.Path)
	if p, err := url.PathUnescape(in.Path); err == nil && p != in.Path {
		add("path", p)
	}
	for k, vs := range in.Header {
		for _, v := range vs {
			add("header:"+http.CanonicalHeaderKey(k), v)
		}
	}
	if len(in.Args) > 0 {
		ps = append(ps, jsonParts("arg:", in.Args)...)
	}
	return ps
}

// jsonParts returns the string values (and member names) of a JSON text at
// prefix+pointer. A body that is not JSON yields nothing; its raw form is
// scanned by the caller. For arguments the leading "/" is dropped:
// arg:content, arg:files/0/content.
func jsonParts(prefix string, raw []byte) []part {
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	var out []part
	for {
		tok, err := dec.ReadToken()
		if err != nil {
			return out
		}
		if tok.Kind() != '"' {
			continue
		}
		ptr := string(dec.StackPointer())
		if prefix == "arg:" {
			ptr = strings.TrimPrefix(ptr, "/")
		}
		out = append(out, part{prefix + ptr, tok.String()})
		if len(out) > 4096 {
			return out
		}
	}
}

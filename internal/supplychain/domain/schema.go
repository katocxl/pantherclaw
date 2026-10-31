// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// maxSchemaDepth bounds how deep a schema is read; a deeper one is flagged as
// unreadable.
const maxSchemaDepth = 64

var errSchemaDepth = errors.New("supplychain: schema nests too deep")

// node is one JSON value of a schema, with the byte range of its text.
type node struct {
	kind       jsontext.Kind
	str        string
	key        string // the member it is the value of
	start, end int
	members    []*member
	items      []*node
}

// member is one object member.
type member struct {
	name       string
	start, end int
	value      *node
}

// parseSchema reads a schema. Duplicate names are refused, so what is read is
// what any reader sees. Nil input gives a nil node, which has nothing in it.
func parseSchema(raw []byte) (*node, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	d := jsontext.NewDecoder(bytes.NewReader(raw))
	n, err := readNode(d, raw, "", 0)
	if err != nil {
		return nil, err
	}
	if _, err := d.ReadToken(); err == nil {
		return nil, errors.New("supplychain: text after the schema")
	}
	return n, nil
}

// tokenStart is where the token after off starts.
func tokenStart(raw []byte, off int) int {
	for off < len(raw) && bytes.IndexByte([]byte(" \t\r\n,:"), raw[off]) >= 0 {
		off++
	}
	return off
}

func readNode(d *jsontext.Decoder, raw []byte, key string, depth int) (*node, error) {
	if depth > maxSchemaDepth {
		return nil, errSchemaDepth
	}
	start := tokenStart(raw, int(d.InputOffset()))
	tok, err := d.ReadToken()
	if err != nil {
		return nil, err
	}
	n := &node{kind: tok.Kind(), key: key, start: start}
	switch n.kind { //nolint:exhaustive // the other kinds hold nothing to check
	case '"':
		n.str = tok.String()
	case '{':
		for d.PeekKind() != '}' {
			mStart := tokenStart(raw, int(d.InputOffset()))
			name, err := d.ReadToken()
			if err != nil {
				return nil, err
			}
			key := name.String() // the next read voids the token
			v, err := readNode(d, raw, key, depth+1)
			if err != nil {
				return nil, err
			}
			n.members = append(n.members, &member{name: key, start: mStart, end: v.end, value: v})
		}
		if _, err := d.ReadToken(); err != nil {
			return nil, err
		}
	case '[':
		for d.PeekKind() != ']' {
			v, err := readNode(d, raw, key, depth+1)
			if err != nil {
				return nil, err
			}
			n.items = append(n.items, v)
		}
		if _, err := d.ReadToken(); err != nil {
			return nil, err
		}
	}
	n.end = int(d.InputOffset())
	return n, nil
}

// get returns the member's value, or nil.
func (n *node) get(name string) *node {
	if n == nil {
		return nil
	}
	for _, m := range n.members {
		if m.name == name {
			return m.value
		}
	}
	return nil
}

// eachString calls f with every string of the schema: member names, with a
// node covering the member, and string values.
func (n *node) eachString(f func(s string, n *node)) {
	if n == nil {
		return
	}
	if n.kind == '"' {
		f(n.str, n)
	}
	for _, m := range n.members {
		f(m.name, &node{start: m.start, end: m.end})
		m.value.eachString(f)
	}
	for _, it := range n.items {
		it.eachString(f)
	}
}

// subschemas are the keywords that hold schemas, by shape.
var (
	schemaOne  = []string{"additionalProperties", "items", "additionalItems", "unevaluatedProperties", "contains", "not", "if", "then", "else"}
	schemaList = []string{"anyOf", "oneOf", "allOf", "items", "prefixItems"}
	schemaMap  = []string{"properties", "patternProperties", "$defs", "definitions"}
)

// eachSchema calls f with s and every schema inside it.
func (n *node) eachSchema(f func(*node)) {
	if n == nil || n.kind != '{' {
		return
	}
	f(n)
	for _, k := range schemaOne {
		n.get(k).eachSchema(f)
	}
	for _, k := range schemaList {
		if v := n.get(k); v != nil {
			for _, it := range v.items {
				it.eachSchema(f)
			}
		}
	}
	for _, k := range schemaMap {
		if v := n.get(k); v != nil {
			for _, m := range v.members {
				m.value.eachSchema(f)
			}
		}
	}
}

// Free-form strings an agent fills in (D210): whatever runs, queries or
// fetches. By name, because a schema does not say what a string means.
var (
	commandNames = []string{"command", "cmd", "commandline", "shell", "shellcommand", "bash", "script", "exec", "execute"}
	sqlNames     = []string{"sql", "sqlquery", "rawsql", "rawquery", "statement", "stmt"}
	urlNames     = []string{"url", "uri", "href", "endpoint", "webhook"}
	urlFormats   = []string{"uri", "url", "iri", "uri-reference", "iri-reference"}
	sqlWord      = regexp.MustCompile(`(?i)\bsql\b`)
	// allPatterns are regular expressions that bound nothing.
	allPatterns = []string{"", ".*", "^.*$", ".+", "^.+$", "(.*)", "^(.*)$", "[\\s\\S]*", "^[\\s\\S]*$"}
)

// bareName is a property name in lower case without separators.
func bareName(s string) string {
	return strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(s))
}

// types lists a schema's "type" keyword.
func types(s *node) []string {
	v := s.get("type")
	if v == nil {
		return nil
	}
	out := []string{v.str}
	for _, it := range v.items {
		out = append(out, it.str)
	}
	return out
}

// freeString reports whether s accepts any string: it allows the string type
// and neither enum, const nor a pattern narrows it. One free branch of an
// anyOf or oneOf frees the whole.
func freeString(s *node) bool {
	if s == nil || s.kind != '{' {
		return s != nil && s.kind == 't'
	}
	if s.get("enum") != nil || s.get("const") != nil {
		return false
	}
	if p := s.get("pattern"); p != nil && !slices.Contains(allPatterns, p.str) {
		return false
	}
	for _, k := range []string{"anyOf", "oneOf"} {
		if v := s.get(k); v != nil {
			return slices.ContainsFunc(v.items, freeString)
		}
	}
	t := types(s)
	return t == nil || slices.Contains(t, "string")
}

// schemaHits is what overbroad found, by class.
type schemaHits struct {
	command, sql, url, open int
	spans                   []Span
}

// property classifies one property.
func (h *schemaHits) property(m *member) {
	s := m.value
	if !freeString(s) {
		return
	}
	name := bareName(m.name)
	format := s.get("format")
	span := Span{FieldInputSchema, m.start, m.end}
	switch {
	case slices.Contains(commandNames, name):
		h.command++
	case slices.Contains(sqlNames, name), name == "query" && sqlWord.MatchString(textOf(s.get("description"))):
		h.sql++
	case slices.Contains(urlNames, name), strings.HasSuffix(name, "url"), strings.HasSuffix(name, "uri"),
		format != nil && slices.Contains(urlFormats, format.str):
		h.url++
	default:
		return
	}
	h.spans = append(h.spans, span)
}

func textOf(n *node) string {
	if n == nil {
		return ""
	}
	return n.str
}

// unbounded reports additionalProperties that takes anything. Leaving the
// keyword out is not flagged: nearly every tool does, and an agent is not
// invited to add anything by it.
func unbounded(s *node) bool {
	v := s.get("additionalProperties")
	return v != nil && (v.kind == 't' || v.kind == '{' && len(v.members) == 0)
}

// overbroad is the overbroad_schema check: free-form command, SQL or URL
// strings, and unbounded additional properties. A schema that could not be
// read or reported is flagged too: it was not checked, so it never passes by
// silence.
func overbroad(t Tool, schema *node, err error) *Flag {
	if t.InputSchemaCut {
		return &Flag{Kind: KindOverbroadSchema, Severity: SeverityMedium, Note: "The input schema is over 64 KiB and was not checked."}
	}
	if err != nil {
		return &Flag{Kind: KindOverbroadSchema, Severity: SeverityMedium, Note: "The input schema could not be read and was not checked."}
	}
	var h schemaHits
	if schema != nil && schema.kind == 't' {
		h.open++
	}
	schema.eachSchema(func(s *node) {
		if v := s.get("properties"); v != nil {
			for _, m := range v.members {
				h.property(m)
			}
		}
		if unbounded(s) {
			h.open++
			h.spans = append(h.spans, Span{FieldInputSchema, s.get("additionalProperties").start, s.get("additionalProperties").end})
		}
	})
	if h.command+h.sql+h.url+h.open == 0 {
		return nil
	}
	sev := SeverityLow
	switch {
	case h.command > 0:
		sev = SeverityHigh
	case h.sql+h.url > 0:
		sev = SeverityMedium
	}
	return &Flag{
		Kind: KindOverbroadSchema, Severity: sev, Spans: capSpans(dedupe(h.spans)),
		Note: fmt.Sprintf("Free-form inputs: %d command, %d SQL and %d URL strings, %d unbounded objects.", h.command, h.sql, h.url, h.open),
	}
}

// shadowing is the tool_shadowing check: the name of a built-in tool, or of a
// tool approved elsewhere with another definition. The same tool on a second
// connection has the same digest and is not shadowing. Names match exactly
// (D210).
func shadowing(t Tool, k Known) *Flag {
	if slices.Contains(k.BuiltIns, t.Name) {
		return &Flag{Kind: KindToolShadowing, Severity: SeverityHigh, Note: "Same name as a tool agents have built in."}
	}
	if slices.ContainsFunc(k.Approved, func(a Approved) bool { return a.Name == t.Name && a.Digest != t.Digest }) {
		return &Flag{Kind: KindToolShadowing, Severity: SeverityHigh, Note: "Same name as an approved tool with another definition."}
	}
	return nil
}

// rugPull is the rug_pull check: what the pinned version reviewed changed
// while that version stayed. The drift check quarantines on the digest
// alone; this says what changed, for the person reviewing it.
func rugPull(t Tool, b *Baseline) *Flag {
	if b == nil || b.Digest == t.Digest || b.Version != t.Version {
		return nil
	}
	if !b.TextKnown {
		return &Flag{Kind: KindRugPull, Severity: SeverityHigh, Note: "The definition changed after approval with no version change."}
	}
	desc := b.Description != t.Description
	schema := b.SchemaDigest != t.InputSchemaDigest
	switch {
	case desc && schema:
		return &Flag{
			Kind: KindRugPull, Severity: SeverityHigh, Spans: firstDiff(b.Description, t.Description),
			Note: "The description and input schema changed after approval with no version change.",
		}
	case desc:
		return &Flag{
			Kind: KindRugPull, Severity: SeverityHigh, Spans: firstDiff(b.Description, t.Description),
			Note: "The description changed after approval with no version change.",
		}
	case schema:
		return &Flag{Kind: KindRugPull, Severity: SeverityHigh, Note: "The input schema changed after approval with no version change."}
	}
	// The digest covers more than these two, so a change is a change (D242).
	return &Flag{Kind: KindRugPull, Severity: SeverityHigh, Note: "The definition changed after approval with no version change."}
}

// firstDiff points at where the description first differs from the approved
// one, through to its end.
func firstDiff(was, now string) []Span {
	i := 0
	for i < len(was) && i < len(now) && was[i] == now[i] {
		i++
	}
	if i == len(now) {
		return nil
	}
	return []Span{{FieldDescription, i, len(now)}}
}

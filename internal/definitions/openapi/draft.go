// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package openapi

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// Draft limits (G0 M31 D953).
const (
	defaultTextLength = 1024
	maxTextLength     = 8192
	defaultListItems  = 32
	maxListItems      = 256
	maxDefinitions    = 256
)

// DefaultIdentifierPattern is a path parameter's pattern when the spec
// gives none.
const DefaultIdentifierPattern = `^[A-Za-z0-9._~-]{1,256}$`

// ErrDraft reports a draft that cannot be written.
var ErrDraft = errors.New("openapi: the package cannot be drafted")

// DraftOptions are what the person drafting names.
type DraftOptions struct {
	// Name and Version are the package's; a name starting with pc. is
	// refused (PantherClaw's own namespace, which org keys cannot sign).
	Name, Version string
	// Operations limits the draft to these operation ids (as written in
	// the spec, or snake case); empty drafts every operation.
	Operations []string
	// Source names the spec file in the draft's header comment.
	Source string
	// Now dates the draft's assurance.valid_until (one year on).
	Now time.Time
}

var (
	queryNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	literalSeg  = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	varSeg      = regexp.MustCompile(`^\{([^{}/]+)\}$`)
)

// Draft writes an unsigned draft tool package from the spec's operations
// (G0 M31 D953, HR-720). Its first key is review_required, which the
// manifest decoder refuses (DRAFT_NOT_REVIEWED): a person reviews each
// definition, removes the key, signs the package with an org key and only
// then imports it. Every write is irreversible, never retried, approved
// over every param and deduplicated over its material params; what could
// not be mapped is a "# review:" comment, never a guess.
func Draft(s *Spec, o DraftOptions) ([]byte, error) {
	switch {
	case !actionir.ValidPackage(o.Name) || o.Name[0] < 'a' || o.Name[0] > 'z':
		return nil, fmt.Errorf("%w: --name %q is not a package name (lowercase letters, digits, . and -)", ErrDraft, o.Name)
	case strings.HasPrefix(o.Name, "pc.") || o.Name == "pc":
		return nil, fmt.Errorf("%w: names starting with pc. are PantherClaw's own; use your organization's prefix", ErrDraft)
	case !actionir.ValidVersion(o.Version):
		return nil, fmt.Errorf("%w: --version %q must be MAJOR.MINOR.PATCH", ErrDraft, o.Version)
	case strings.Count(o.Name, ".") > 6:
		return nil, fmt.Errorf("%w: --name %q has more than 7 parts", ErrDraft, o.Name)
	}
	prefix := strings.ReplaceAll(o.Name, "-", "_")
	publisher, _, _ := strings.Cut(o.Name, ".")
	ops := slices.DeleteFunc(slices.Clone(s.Operations), func(op Operation) bool {
		return len(o.Operations) > 0 && !slices.Contains(o.Operations, op.ID) && !slices.Contains(o.Operations, op.Snake)
	})
	for _, want := range o.Operations {
		if !slices.ContainsFunc(s.Operations, func(op Operation) bool { return op.ID == want || op.Snake == want }) {
			return nil, fmt.Errorf("%w: the spec has no operation %q", ErrDraft, want)
		}
	}
	if len(ops) == 0 || len(ops) > maxDefinitions {
		return nil, fmt.Errorf("%w: 1..%d operations to draft, not %d", ErrDraft, maxDefinitions, len(ops))
	}
	reasons := []string{
		"drafted from an OpenAPI spec: check every definition's target, effects, params, mappings and dispatch against the API",
		"set the connection's base URL (the spec's first server is " + quoteOr(s.Server, "not given") + ") and its credential",
		"assurance.reviewed_by and valid_until are placeholders: name the people who reviewed the package",
	}
	var defs []*yaml.Node
	seen := map[string]bool{}
	var text, omitted bool
	for _, op := range ops {
		d, notes, err := definition(prefix, publisher, op, o.Now)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("operation %s was left out: %v", op.ID, err))
			continue
		}
		if seen[op.Snake] {
			reasons = append(reasons, fmt.Sprintf("operation %s was left out: its name %s is taken", op.ID, op.Snake))
			continue
		}
		seen[op.Snake] = true
		text = text || notes.text
		omitted = omitted || len(op.Omitted) > 0
		defs = append(defs, d)
	}
	if len(defs) == 0 {
		return nil, fmt.Errorf("%w: no operation could be drafted: %s", ErrDraft, strings.Join(reasons[3:], "; "))
	}
	if text {
		reasons = append(reasons, "text params are untrusted and never sent from a template: change each to identifier, enum or content, or remove it")
	}
	if omitted {
		reasons = append(reasons, "parts of some operations were left out; each is a \"# review:\" comment")
	}
	reasonNodes := make([]*yaml.Node, 0, len(reasons))
	for _, r := range reasons {
		reasonNodes = append(reasonNodes, str(r))
	}
	top := mapping(
		"review_required", seq(reasonNodes...),
		"format", integer(1),
		"name", str(o.Name),
		"version", str(o.Version),
		"publisher", str(publisher),
		"summary", str(summaryOf(o.Name)),
		"definitions", seq(defs...),
	)
	top.Content[0].HeadComment = "Drafted by pclaw package draft openapi from " + quoteOr(o.Source, "a spec") + ".\n" +
		"Not reviewed: the package does not load while review_required is present.\n" +
		"Remove it only after every item is settled, then sign with an org package key (pclaw package sign)."
	doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{top}}
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDraft, err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDraft, err)
	}
	return b.Bytes(), nil
}

func quoteOr(s, empty string) string {
	if s == "" {
		return empty
	}
	return strconv.Quote(s)
}

func summaryOf(name string) string { return "Operations drafted from the OpenAPI spec of " + name }

type draftNotes struct{ text bool }

// param is one drafted param: its snake-case name and its spec.
type param struct {
	snake    string
	p        Param
	typ      string
	material bool
}

// definition drafts one operation.
func definition(prefix, publisher string, op Operation, now time.Time) (*yaml.Node, draftNotes, error) {
	var notes draftNotes
	segs := strings.Split(strings.TrimPrefix(op.Path, "/"), "/")
	byName := map[string]Param{}
	for _, p := range op.Params {
		if p.In == "path" {
			byName[p.Name] = p
		}
	}
	// The target is the last path parameter, the object the operation
	// acts on; without one, the service itself.
	targetVar := ""
	for _, seg := range segs {
		if m := varSeg.FindStringSubmatch(seg); m != nil {
			targetVar = m[1]
		} else if seg == "" {
			return nil, notes, fmt.Errorf("the path %q has an empty segment", op.Path)
		} else if !literalSeg.MatchString(seg) {
			return nil, notes, fmt.Errorf("path segment %q mixes text and a parameter", seg)
		}
	}
	operation := prefix + "." + op.Snake
	if !actionir.ValidOperation(operation) {
		return nil, notes, fmt.Errorf("%q is not an operation name", operation)
	}
	var params []param
	used := map[string]bool{}
	omitted := slices.Clone(op.Omitted)
	for _, p := range op.Params {
		if p.In == "path" && p.Name == targetVar {
			continue
		}
		if (p.In == "query" || p.In == "body") && !queryNameRe.MatchString(p.Name) {
			omitted = append(omitted, fmt.Sprintf("%s %q (its name cannot be mapped)", p.In, p.Name))
			continue
		}
		if p.In == "query" && p.Schema.Type == "array" {
			omitted = append(omitted, fmt.Sprintf("query %q (a list in a query)", p.Name))
			continue
		}
		snake := Snake(p.Name)
		if used[snake] {
			omitted = append(omitted, fmt.Sprintf("%s %q (its name %s is taken)", p.In, p.Name, snake))
			continue
		}
		used[snake] = true
		typ := paramType(p)
		notes.text = notes.text || typ == "text"
		params = append(params, param{snake: snake, p: p, typ: typ, material: typ != "text"})
	}
	if targetVar != "" {
		if _, ok := byName[targetVar]; !ok {
			return nil, notes, fmt.Errorf("path parameter %q is not declared", targetVar)
		}
	}
	write := op.Method != http.MethodGet
	access := "read"
	if write {
		access = "write"
	}
	summary := op.Summary
	if summary == "" || len(summary) > 200 || strings.ContainsAny(summary, "\r\n") {
		summary = op.Method + " " + op.Path
	}
	target, extractTarget := targetOf(prefix, segs, targetVar, byName)
	pairs := []any{
		"operation", str(operation),
		"summary", str(summary),
		"access", str(access),
		"target", target,
		"params", paramsNode(params),
	}
	if write {
		pairs = append(pairs,
			"effects", seq(mapping("kind", str("api.write"), "description", str("Calls "+op.Method+" "+op.Path+" on the API"))),
			"reversibility", str("irreversible"),
			"dedupe_key", dedupeNode(params),
			"retry", mapping("safe", boolean(false), "on_unknown", str("fail")),
			"approval", mapping("title", str(clip(summary, 120)+" on {target.id}"), "fields", approvalFields(params)),
		)
	} else {
		pairs = append(pairs,
			"effects", seq(mapping("kind", str("none"), "description", str("Reads only"))),
			"reversibility", str("reversible"),
			"retry", mapping("safe", boolean(true), "on_unknown", str("fail")),
		)
	}
	pairs = append(pairs,
		"assurance", mapping(
			"basis", str("declared"),
			"reviewed_by", seq(str(publisher)),
			"valid_until", str(now.AddDate(1, 0, 0).UTC().Format(time.DateOnly)),
		),
		"mappings", seq(httpMapping(prefix, op, segs, extractTarget, params)),
		"dispatch", mapping("http", dispatchNode(op, segs, targetVar, params)),
	)
	d := mapping(pairs...)
	var head []string
	for _, n := range op.Notes {
		head = append(head, "review: "+n)
	}
	for _, x := range omitted {
		head = append(head, "review: left out "+x)
	}
	if targetVar == "" {
		head = append(head, "review: the operation names no object; its target is the service itself")
	}
	d.Content[0].HeadComment = strings.Join(head, "\n")
	return d, notes, nil
}

// paramType maps a schema to a param type (D953).
func paramType(p Param) string {
	switch {
	case p.In == "path":
		return "identifier"
	case len(p.Schema.Enum) > 0:
		return "enum"
	}
	switch p.Schema.Type {
	case "integer":
		return "integer"
	case "number":
		return "decimal"
	case "boolean":
		return "boolean"
	case "array":
		return "identifier_list"
	}
	return "text"
}

// targetOf is the definition's target and its extraction: the last path
// parameter, typed by the literal segment before it.
func targetOf(prefix string, segs []string, targetVar string, byName map[string]Param) (*yaml.Node, string) {
	if targetVar == "" {
		return mapping(
			"type", str(prefix+".service"),
			"id_pattern", str("^service$"),
			"account", str("none"),
		), "'service'"
	}
	kind := "resource"
	for i, seg := range segs {
		if seg == "{"+targetVar+"}" && i > 0 && literalSeg.MatchString(segs[i-1]) {
			kind = Snake(segs[i-1])
		}
	}
	n := mapping(
		"type", str(prefix+"."+kind),
		"id_pattern", str(identifierPattern(byName[targetVar].Schema)),
		"account", str("none"),
	)
	if byName[targetVar].Schema.Pattern == "" {
		n.Content[2].HeadComment = "review: the spec gives no pattern for " + targetVar + "; narrow this one"
	}
	return n, "path." + Snake(targetVar)
}

// identifierPattern is a path parameter's anchored pattern: the spec's,
// anchored, when it compiles, or the default.
func identifierPattern(s Schema) string {
	p := s.Pattern
	if p == "" {
		return DefaultIdentifierPattern
	}
	if !strings.HasPrefix(p, "^") || !strings.HasSuffix(p, "$") {
		p = "^(?:" + strings.TrimSuffix(strings.TrimPrefix(p, "^"), "$") + ")$"
	}
	if _, err := regexp.Compile(p); err != nil || len(p) > 256 {
		return DefaultIdentifierPattern
	}
	return p
}

func paramsNode(params []param) *yaml.Node {
	pairs := make([]any, 0, 2*len(params))
	for _, p := range params {
		spec := []any{"type", str(p.typ)}
		if p.material {
			spec = append(spec, "material", boolean(true))
		}
		if p.p.Required {
			spec = append(spec, "required", boolean(true))
		}
		switch p.typ {
		case "text":
			n := p.p.Schema.MaxLength
			if n <= 0 {
				n = defaultTextLength
			}
			spec = append(spec, "max_length", integer(min(n, maxTextLength)))
		case "enum":
			vals := make([]*yaml.Node, 0, len(p.p.Schema.Enum))
			for _, v := range p.p.Schema.Enum {
				vals = append(vals, str(v))
			}
			spec = append(spec, "values", flow(seq(vals...)))
		case "identifier":
			spec = append(spec, "pattern", str(identifierPattern(p.p.Schema)))
		case "integer", "decimal":
			spec = append(spec, "unit", str("count"))
			if p.p.Schema.Minimum != "" {
				spec = append(spec, "min", str(p.p.Schema.Minimum))
			}
			if p.p.Schema.Maximum != "" {
				spec = append(spec, "max", str(p.p.Schema.Maximum))
			}
		case "identifier_list":
			n := p.p.Schema.MaxItems
			if n <= 0 {
				n = defaultListItems
			}
			spec = append(spec, "max_items", integer(min(n, maxListItems)))
			if p.p.Schema.Items != nil && p.p.Schema.Items.Pattern != "" {
				spec = append(spec, "pattern", str(identifierPattern(*p.p.Schema.Items)))
			}
		}
		node := mapping(spec...)
		key := str(p.snake)
		switch p.typ {
		case "text":
			key.HeadComment = "review: text is never sent from a template; make it identifier, enum or content"
		case "integer", "decimal":
			key.HeadComment = "review: the unit is a placeholder"
		}
		pairs = append(pairs, key, node)
	}
	m := mapping(pairs...)
	if len(params) == 0 {
		m.Style = yaml.FlowStyle
	}
	return m
}

func dedupeNode(params []param) *yaml.Node {
	items := []*yaml.Node{str("target.id")}
	for _, p := range params {
		if p.material {
			items = append(items, str("params."+p.snake))
		}
	}
	return flow(seq(items...))
}

func approvalFields(params []param) *yaml.Node {
	items := []*yaml.Node{str("target.id")}
	for _, p := range params {
		items = append(items, str("params."+p.snake))
	}
	return flow(seq(items...))
}

// extraction is a param's CEL extraction from the agent's request.
func extraction(p param) string {
	src := map[string]string{"path": "path.", "query": "query.", "body": "input."}[p.p.In]
	field := p.snake
	if p.p.In != "path" {
		field = p.p.Name
	}
	optional := !p.p.Required && p.p.In != "path"
	ref := src + field
	if optional {
		ref = src + "?" + field
	}
	// conv applies f to the value; an optional value through optMap.
	conv := func(f func(v string) string) string {
		if !optional {
			return f(src + field)
		}
		return ref + ".optMap(v, " + f("v") + ")"
	}
	switch {
	case p.typ == "integer":
		return conv(func(v string) string { return "int(" + v + ")" })
	case p.typ == "decimal" && p.p.In == "body":
		return conv(func(v string) string { return "decimal(string(" + v + "))" })
	case p.typ == "decimal":
		return conv(func(v string) string { return "decimal(" + v + ")" })
	case p.typ == "boolean" && p.p.In == "query":
		return conv(func(v string) string { return v + " == 'true'" })
	}
	return ref
}

// httpMapping is the agent-facing route of the operation: the spec's own
// method and path, so a request the agent sends through the gateway's
// http face maps onto the definition.
func httpMapping(prefix string, op Operation, segs []string, extractTarget string, params []param) *yaml.Node {
	path := make([]string, len(segs))
	for i, seg := range segs {
		if m := varSeg.FindStringSubmatch(seg); m != nil {
			path[i] = "{" + Snake(m[1]) + "}"
			continue
		}
		path[i] = seg
	}
	pairs := make([]any, 0, 2*len(params))
	for _, p := range params {
		pairs = append(pairs, p.snake, str(extraction(p)))
	}
	ex := mapping(pairs...)
	if len(params) == 0 {
		ex.Style = yaml.FlowStyle
	}
	route := strings.ReplaceAll(strings.ReplaceAll(prefix+"-"+op.Snake, "_", "-"), ".", "-")
	if len(route) > 64 {
		route = strings.TrimRight(route[:64], "-")
	}
	m := mapping(
		"channel", str("http"),
		"method", str(op.Method),
		"path", str("/"+strings.Join(path, "/")),
		"route", str(route),
		"extract", mapping("target_id", str(extractTarget), "params", ex),
	)
	m.Content[0].HeadComment = "review: the extraction expressions are drafted; check each against the API"
	return m
}

func dispatchNode(op Operation, segs []string, targetVar string, params []param) *yaml.Node {
	snakeOf := map[string]string{}
	for _, p := range params {
		snakeOf[p.p.In+" "+p.p.Name] = p.snake
	}
	path := make([]string, len(segs))
	for i, seg := range segs {
		m := varSeg.FindStringSubmatch(seg)
		switch {
		case m == nil:
			path[i] = seg
		case m[1] == targetVar:
			path[i] = "{target.id}"
		default:
			path[i] = "{params." + snakeOf["path "+m[1]] + "}"
		}
	}
	pairs := []any{"method", str(op.Method), "path", str("/" + strings.Join(path, "/"))}
	var query, body []any
	for _, p := range params {
		switch p.p.In {
		case "query":
			query = append(query, p.p.Name, str("params."+p.snake))
		case "body":
			body = append(body, p.p.Name, str("params."+p.snake))
		}
	}
	if len(query) > 0 {
		pairs = append(pairs, "query", mapping(query...))
	}
	if len(body) > 0 {
		pairs = append(pairs, "body", mapping(body...))
	}
	return mapping(pairs...)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n])
}

// YAML node helpers. Every string is tagged !!str, so the encoder quotes
// what would otherwise read as another type (a version, a date, true).

func str(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }

func integer(n int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(n)}
}

func boolean(b bool) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(b)}
}

func seq(items ...*yaml.Node) *yaml.Node {
	return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: items}
}

func flow(n *yaml.Node) *yaml.Node { n.Style = yaml.FlowStyle; return n }

// mapping builds a mapping from key, value pairs: a key is a string or a
// *yaml.Node (to carry a comment); a value is a *yaml.Node.
func mapping(pairs ...any) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for i := 0; i+1 < len(pairs); i += 2 {
		k, ok := pairs[i].(*yaml.Node)
		if !ok {
			k = str(pairs[i].(string))
		}
		v, _ := pairs[i+1].(*yaml.Node)
		m.Content = append(m.Content, k, v)
	}
	return m
}

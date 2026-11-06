// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package openapi is a minimal reader of OpenAPI 3.0 and 3.1 documents
// (G0 M31 D953, D954): enough to draft a tool package from a spec and to
// serve a spec's examples from a simulator. It reads JSON or YAML, follows
// local $refs only (#/…, at most 16 deep) and refuses Swagger 2 and any
// external reference. It is not a validator of the spec itself: what it
// cannot map is reported as left out, never guessed.
package openapi

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Limits.
const (
	MaxSpecBytes = 16 << 20
	MaxRefDepth  = 16
)

// Errors of a spec that cannot be read.
var (
	ErrSpec        = errors.New("openapi: not a readable OpenAPI 3.0 or 3.1 document")
	ErrSwagger     = fmt.Errorf("%w: Swagger 2 documents are not read; convert the spec to OpenAPI 3 first", ErrSpec)
	ErrExternalRef = fmt.Errorf("%w: only local references (#/…) are followed", ErrSpec)
	ErrRefDepth    = fmt.Errorf("%w: references nest deeper than %d", ErrSpec, MaxRefDepth)
)

// Methods are the operations read from a path item, in this order.
var Methods = []string{"get", "put", "post", "patch", "delete"}

// Spec is what is read from a document.
type Spec struct {
	Version string
	// Server is servers[0].url: a hint for the connection's base URL.
	Server     string
	Operations []Operation
}

// Operation is one operation of a path item.
type Operation struct {
	// ID is the operationId as written; Snake is its snake-case form. An
	// operation without an id gets one from its method and path, and
	// says so in Notes.
	ID, Snake string
	Method    string // upper case
	Path      string // the path template as written
	Summary   string
	Params    []Param // path and query parameters, then top-level body properties
	// Omitted are the parts of the operation that are not mapped.
	Omitted []string
	// Notes are what a reviewer should check beyond the omissions.
	Notes []string
	// Status is the first 2xx response code (200 when none is numeric);
	// Example is that response's first JSON example, or nil.
	Status  int
	Example any
}

// Param is one mapped parameter.
type Param struct {
	Name     string // as written in the spec
	In       string // path, query or body
	Required bool
	Schema   Schema
}

// Schema is the part of a JSON schema a parameter is mapped from.
type Schema struct {
	Type      string // string, integer, number, boolean, array
	Enum      []string
	Pattern   string
	MaxLength int
	MaxItems  int
	Minimum   string
	Maximum   string
	// Items is an array's item schema (strings only are mapped).
	Items *Schema
	// Unmapped says why the schema is left out, when it is.
	Unmapped string
}

// Parse reads an OpenAPI 3.0.x or 3.1.x document, JSON or YAML.
func Parse(raw []byte) (*Spec, error) {
	if len(raw) == 0 || len(raw) > MaxSpecBytes {
		return nil, fmt.Errorf("%w: size %d outside 1..%d bytes", ErrSpec, len(raw), MaxSpecBytes)
	}
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSpec, err)
	}
	root, ok := normalize(doc, 0).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: the document is not an object", ErrSpec)
	}
	if _, ok := root["swagger"]; ok {
		return nil, ErrSwagger
	}
	v, _ := root["openapi"].(string)
	if !strings.HasPrefix(v, "3.0.") && !strings.HasPrefix(v, "3.1.") {
		return nil, fmt.Errorf("%w: openapi %q is not 3.0.x or 3.1.x", ErrSpec, v)
	}
	r := &reader{root: root}
	s := &Spec{Version: v}
	if servers, ok := root["servers"].([]any); ok && len(servers) > 0 {
		if first, ok := servers[0].(map[string]any); ok {
			s.Server, _ = first["url"].(string)
		}
	}
	paths, err := r.object(root["paths"], 0)
	if err != nil {
		return nil, err
	}
	for _, p := range sortedKeys(paths) {
		item, err := r.object(paths[p], 0)
		if err != nil {
			return nil, err
		}
		shared, err := r.list(item["parameters"])
		if err != nil {
			return nil, err
		}
		for _, m := range Methods {
			raw, ok := item[m]
			if !ok {
				continue
			}
			op, err := r.operation(p, m, raw, shared)
			if err != nil {
				return nil, err
			}
			s.Operations = append(s.Operations, op)
		}
	}
	return s, nil
}

// maxNesting bounds how deep a document is walked.
const maxNesting = 256

// normalize turns every YAML mapping into map[string]any, a key such as an
// unquoted response code 200 becoming its text, so JSON and YAML read
// alike. Anything nested deeper than maxNesting is dropped.
func normalize(n any, depth int) any {
	if depth > maxNesting {
		return nil
	}
	switch v := n.(type) {
	case map[string]any:
		for k, x := range v {
			v[k] = normalize(x, depth+1)
		}
		return v
	case map[any]any:
		out := make(map[string]any, len(v))
		for k, x := range v {
			out[fmt.Sprint(k)] = normalize(x, depth+1)
		}
		return out
	case []any:
		for i, x := range v {
			v[i] = normalize(x, depth+1)
		}
		return v
	}
	return n
}

type reader struct{ root map[string]any }

// resolve follows a node's $ref, if it has one, at most MaxRefDepth deep.
func (r *reader) resolve(n any, depth int) (any, error) {
	for {
		m, ok := n.(map[string]any)
		if !ok {
			return n, nil
		}
		ref, ok := m["$ref"].(string)
		if !ok {
			return n, nil
		}
		if depth++; depth > MaxRefDepth {
			return nil, ErrRefDepth
		}
		if !strings.HasPrefix(ref, "#/") {
			return nil, fmt.Errorf("%w: %q", ErrExternalRef, ref)
		}
		var cur any = r.root
		for _, tok := range strings.Split(ref[2:], "/") {
			tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
			obj, ok := cur.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%w: %q does not resolve", ErrSpec, ref)
			}
			if cur, ok = obj[tok]; !ok {
				return nil, fmt.Errorf("%w: %q does not resolve", ErrSpec, ref)
			}
		}
		n = cur
	}
}

func (r *reader) object(n any, depth int) (map[string]any, error) {
	v, err := r.resolve(n, depth)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return map[string]any{}, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: an object was expected", ErrSpec)
	}
	return m, nil
}

func (r *reader) list(n any) ([]any, error) {
	v, err := r.resolve(n, 0)
	if err != nil || v == nil {
		return nil, err
	}
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: a list was expected", ErrSpec)
	}
	return l, nil
}

func (r *reader) operation(path, method string, raw any, shared []any) (Operation, error) {
	o, err := r.object(raw, 0)
	if err != nil {
		return Operation{}, err
	}
	op := Operation{Method: strings.ToUpper(method), Path: path, Status: 200}
	op.ID, _ = o["operationId"].(string)
	op.Summary, _ = o["summary"].(string)
	if op.ID == "" {
		op.ID = method + " " + path
		op.Notes = append(op.Notes, "the spec gives no operationId; the name is made from the method and path")
	}
	op.Snake = Snake(op.ID)
	params, err := r.list(o["parameters"])
	if err != nil {
		return Operation{}, err
	}
	// An operation's parameter overrides the path item's of the same name
	// and location.
	seen := map[string]bool{}
	for _, list := range [][]any{params, shared} {
		for _, p := range list {
			pm, err := r.object(p, 0)
			if err != nil {
				return Operation{}, err
			}
			name, _ := pm["name"].(string)
			in, _ := pm["in"].(string)
			if seen[in+" "+name] {
				continue
			}
			seen[in+" "+name] = true
			switch in {
			case "path", "query":
			default:
				op.Omitted = append(op.Omitted, fmt.Sprintf("%s parameter %q", in, name))
				continue
			}
			required, _ := pm["required"].(bool)
			sch, err := r.schema(pm["schema"], 0)
			if err != nil {
				return Operation{}, err
			}
			if sch.Unmapped != "" {
				op.Omitted = append(op.Omitted, fmt.Sprintf("%s parameter %q (%s)", in, name, sch.Unmapped))
				continue
			}
			op.Params = append(op.Params, Param{Name: name, In: in, Required: required || in == "path", Schema: sch})
		}
	}
	if err := r.body(&op, o["requestBody"]); err != nil {
		return Operation{}, err
	}
	if err := r.response(&op, o["responses"]); err != nil {
		return Operation{}, err
	}
	return op, nil
}

// body maps the top-level properties of a JSON request body.
func (r *reader) body(op *Operation, raw any) error {
	if raw == nil {
		return nil
	}
	b, err := r.object(raw, 0)
	if err != nil {
		return err
	}
	content, err := r.object(b["content"], 0)
	if err != nil {
		return err
	}
	media, ok := content["application/json"]
	if !ok {
		for _, k := range sortedKeys(content) {
			op.Omitted = append(op.Omitted, fmt.Sprintf("a %s request body", k))
		}
		return nil
	}
	for _, k := range sortedKeys(content) {
		if k != "application/json" {
			op.Omitted = append(op.Omitted, fmt.Sprintf("the %s form of the request body", k))
		}
	}
	mm, err := r.object(media, 0)
	if err != nil {
		return err
	}
	s, err := r.object(mm["schema"], 0)
	if err != nil {
		return err
	}
	if composite(s) != "" {
		op.Omitted = append(op.Omitted, "the request body ("+composite(s)+")")
		return nil
	}
	if t, _ := s["type"].(string); t != "" && t != "object" {
		op.Omitted = append(op.Omitted, "a request body that is not an object")
		return nil
	}
	props, err := r.object(s["properties"], 0)
	if err != nil {
		return err
	}
	required := map[string]bool{}
	if req, ok := s["required"].([]any); ok {
		for _, x := range req {
			if n, ok := x.(string); ok {
				required[n] = true
			}
		}
	}
	for _, name := range sortedKeys(props) {
		sch, err := r.schema(props[name], 0)
		if err != nil {
			return err
		}
		if sch.Unmapped != "" {
			op.Omitted = append(op.Omitted, fmt.Sprintf("body property %q (%s)", name, sch.Unmapped))
			continue
		}
		op.Params = append(op.Params, Param{Name: name, In: "body", Required: required[name], Schema: sch})
	}
	return nil
}

// response reads the first 2xx response and its first JSON example.
func (r *reader) response(op *Operation, raw any) error {
	res, err := r.object(raw, 0)
	if err != nil {
		return err
	}
	for _, code := range sortedKeys(res) {
		n, err := strconv.Atoi(code)
		if err != nil || n < 200 || n > 299 {
			if code == "2XX" {
				n = 200
			} else {
				continue
			}
		}
		op.Status = n
		resp, err := r.object(res[code], 0)
		if err != nil {
			return err
		}
		content, err := r.object(resp["content"], 0)
		if err != nil {
			return err
		}
		media, ok := content["application/json"]
		if !ok {
			return nil
		}
		mm, err := r.object(media, 0)
		if err != nil {
			return err
		}
		if ex, ok := mm["example"]; ok {
			op.Example = ex
			return nil
		}
		if exs, err := r.object(mm["examples"], 0); err == nil {
			for _, k := range sortedKeys(exs) {
				e, err := r.object(exs[k], 0)
				if err != nil {
					return err
				}
				if v, ok := e["value"]; ok {
					op.Example = v
					return nil
				}
			}
		}
		if s, err := r.object(mm["schema"], 0); err == nil {
			if ex, ok := s["example"]; ok {
				op.Example = ex
			}
		}
		return nil
	}
	return nil
}

// composite names a schema's oneOf, anyOf or allOf, which is not mapped.
func composite(s map[string]any) string {
	for _, k := range []string{"oneOf", "anyOf", "allOf"} {
		if _, ok := s[k]; ok {
			return k
		}
	}
	return ""
}

// schema reads the parts of a parameter's schema that are mapped.
func (r *reader) schema(raw any, depth int) (Schema, error) {
	s, err := r.object(raw, depth)
	if err != nil {
		return Schema{}, err
	}
	if c := composite(s); c != "" {
		return Schema{Unmapped: c}, nil
	}
	out := Schema{}
	switch t := s["type"].(type) {
	case string:
		out.Type = t
	case []any:
		// OpenAPI 3.1: a type list such as [string, "null"].
		for _, x := range t {
			if x, ok := x.(string); ok && x != "null" {
				if out.Type != "" {
					return Schema{Unmapped: "more than one type"}, nil
				}
				out.Type = x
			}
		}
	}
	switch out.Type {
	case "string":
		if f, _ := s["format"].(string); f == "binary" || f == "byte" {
			return Schema{Unmapped: "a file"}, nil
		}
		out.Pattern, _ = s["pattern"].(string)
		out.MaxLength = intOf(s["maxLength"])
		if e, ok := s["enum"].([]any); ok {
			for _, v := range e {
				str, ok := v.(string)
				if !ok {
					return Schema{Unmapped: "an enum that is not all strings"}, nil
				}
				out.Enum = append(out.Enum, str)
			}
		}
	case "integer", "number":
		out.Minimum, out.Maximum = numOf(s["minimum"]), numOf(s["maximum"])
	case "boolean":
	case "array":
		items, err := r.schema(s["items"], depth+1)
		if err != nil {
			return Schema{}, err
		}
		if items.Type != "string" || items.Unmapped != "" || len(items.Enum) > 0 {
			return Schema{Unmapped: "an array of anything but plain strings"}, nil
		}
		out.Items = &items
		out.MaxItems = intOf(s["maxItems"])
	case "object":
		return Schema{Unmapped: "a nested object"}, nil
	default:
		return Schema{Unmapped: "no supported type"}, nil
	}
	return out, nil
}

func intOf(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case uint64:
		return int(min(n, 1<<31))
	case float64:
		if n >= 0 && n < 1<<31 && n == float64(int(n)) {
			return int(n)
		}
	}
	return 0
}

func numOf(v any) string {
	switch n := v.(type) {
	case int:
		return strconv.Itoa(n)
	case int64:
		return strconv.FormatInt(n, 10)
	case uint64:
		return strconv.FormatUint(n, 10)
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64)
	}
	return ""
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

var (
	camelRe    = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	acronymRe  = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`)
	nonAlnumRe = regexp.MustCompile(`[^a-z0-9]+`)
)

// Snake is the snake-case form of an operation id or a parameter name:
// lower case letters, digits and single underscores, starting with a
// letter, at most 64 bytes.
func Snake(s string) string {
	s = acronymRe.ReplaceAllString(s, "${1}_${2}")
	s = camelRe.ReplaceAllString(s, "${1}_${2}")
	s = strings.Trim(nonAlnumRe.ReplaceAllString(strings.ToLower(s), "_"), "_")
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		s = "x_" + s
	}
	if len(s) > 64 {
		s = strings.TrimRight(s[:64], "_")
	}
	return s
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command apischema completes the generated Connect OpenAPI schema where the
// pinned generator loses facts the server enforces (G0 M13, API assurance):
//
//   - a protovalidate `gte: 0` on a numeric field becomes `minimum: 0`; the
//     generator sets it, but its serializer drops a zero minimum;
//   - every operation that takes a request body documents the bodiless 415
//     Connect answers for a missing or unsupported Content-Type;
//   - the optional Connect-Timeout-Ms header is not published: a client may
//     send it, but a tiny value legitimately ends in deadline_exceeded
//     (504), which is not a property of the operation;
//   - Connect-Protocol-Version is optional: the Connect protocol says
//     clients should send it, and the server accepts calls without it, so
//     bare HTTP callers and curl examples keep working;
//   - in request messages, where a field's default passes its own
//     protovalidate rules, the property also accepts null (the ProtoJSON
//     spec reads null as the default) and, for a string without presence,
//     the empty string;
//     where the default breaks them, omitting the field is refused like the
//     default, so the property is required;
//   - an enum field's `in` and `not_in` rules are given by value name, as
//     ProtoJSON writes enums (the generator only lists numbers).
//
// It runs from `task api:schema` and rewrites the file in place, keeping the
// generator's key order and formatting so the nightly drift check still works.
//
//	go run ./internal/apischema docs/api/pantherclaw.openapi.json
package main

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	_ "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1" // Registers the API descriptors.
)

const (
	// unsupportedMedia is the response Connect sends without a body.
	unsupportedMedia = "Unsupported media type, no body"
	// timeoutHeader and its component are left out of the schema.
	timeoutHeader, timeoutSchema = "Connect-Timeout-Ms", "connect-timeout-header"
	// versionHeader is documented but not required.
	versionHeader = "Connect-Protocol-Version"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: apischema <openapi.json>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "apischema:", err)
		os.Exit(1)
	}
}

func run(path string) error {
	in, err := os.ReadFile(path) //nolint:gosec // Repository file named by the Taskfile.
	if err != nil {
		return err
	}
	facts, err := Collect(protoregistry.GlobalFiles)
	if err != nil {
		return err
	}
	out, err := Fix(in, facts)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644) //nolint:gosec // A committed, world-readable document.
}

// field names one property of a component schema.
type field struct{ schema, property string }

// Facts are what the descriptors say about the fields of every message.
type Facts struct {
	// Minimums are numeric fields with `gte: 0`.
	Minimums map[field]bool
	// ZeroInvalid are fields whose default breaks their own rules.
	ZeroInvalid map[field]bool
	// Strings are singular string fields without presence, where "" is the
	// default; for an `optional` one, "" is a set value and validated.
	Strings map[field]bool
	// Enums are enum fields (or items) with `in` or `not_in` rules.
	Enums map[field]EnumRule
}

// EnumRule restricts an enum field, or each item of a repeated one.
type EnumRule struct {
	In, NotIn []string
}

// Collect reads the Facts from the registered descriptors.
func Collect(files *protoregistry.Files) (Facts, error) {
	invalid, err := zeroInvalid(files)
	if err != nil {
		return Facts{}, err
	}
	f := Facts{Minimums: zeroMinimums(files), ZeroInvalid: invalid, Strings: map[field]bool{}, Enums: map[field]EnumRule{}}
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		walkMessages(fd.Messages(), func(md protoreflect.MessageDescriptor) {
			for i := range md.Fields().Len() {
				fd := md.Fields().Get(i)
				key := field{string(md.FullName()), fd.JSONName()}
				if fd.Kind() == protoreflect.StringKind && fd.Cardinality() != protoreflect.Repeated && !fd.HasPresence() {
					f.Strings[key] = true
				}
				if fd.Kind() != protoreflect.EnumKind {
					continue
				}
				rules, ok := proto.GetExtension(fd.Options(), validate.E_Field).(*validate.FieldRules)
				if !ok || rules == nil {
					continue
				}
				if fd.IsList() {
					rules = rules.GetRepeated().GetItems()
				}
				er := rules.GetEnum()
				names := func(nums []int32) []string {
					out := make([]string, 0, len(nums))
					for _, n := range nums {
						if v := fd.Enum().Values().ByNumber(protoreflect.EnumNumber(n)); v != nil {
							out = append(out, string(v.Name()))
						}
					}
					return out
				}
				if len(er.GetIn()) > 0 || len(er.GetNotIn()) > 0 {
					f.Enums[key] = EnumRule{In: names(er.GetIn()), NotIn: names(er.GetNotIn())}
				}
			}
		})
		return true
	})
	return f, nil
}

// zeroMinimums lists every numeric field whose protovalidate rules say
// `gte: 0`, directly or for each item of a repeated field.
func zeroMinimums(files *protoregistry.Files) map[field]bool {
	out := map[field]bool{}
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		walkMessages(fd.Messages(), func(md protoreflect.MessageDescriptor) {
			for i := range md.Fields().Len() {
				f := md.Fields().Get(i)
				rules, ok := proto.GetExtension(f.Options(), validate.E_Field).(*validate.FieldRules)
				if !ok || rules == nil {
					continue
				}
				if f.IsList() {
					rules = rules.GetRepeated().GetItems()
				}
				if gteZero(rules) {
					out[field{string(md.FullName()), f.JSONName()}] = true
				}
			}
		})
		return true
	})
	return out
}

func walkMessages(ms protoreflect.MessageDescriptors, fn func(protoreflect.MessageDescriptor)) {
	for i := range ms.Len() {
		md := ms.Get(i)
		fn(md)
		walkMessages(md.Messages(), fn)
	}
}

// gteZero reports whether the numeric rule set (int32, double, ...) carries
// an explicit `gte` of zero.
func gteZero(rules *validate.FieldRules) bool {
	if rules == nil {
		return false
	}
	m := rules.ProtoReflect()
	which := m.WhichOneof(m.Descriptor().Oneofs().ByName("type"))
	if which == nil || which.Kind() != protoreflect.MessageKind {
		return false
	}
	typed := m.Get(which).Message()
	gte := typed.Descriptor().Fields().ByName("gte")
	if gte == nil || !typed.Has(gte) {
		return false
	}
	switch v := typed.Get(gte).Interface().(type) {
	case int32, int64, uint32, uint64:
		return fmt.Sprint(v) == "0"
	case float32:
		return v == 0
	case float64:
		return v == 0
	}
	return false
}

// zeroInvalid lists every field whose default value, in an otherwise empty
// message, breaks one of the field's own protovalidate rules.
func zeroInvalid(files *protoregistry.Files) (map[field]bool, error) {
	v, err := protovalidate.New()
	if err != nil {
		return nil, err
	}
	out := map[field]bool{}
	var walkErr error
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		walkMessages(fd.Messages(), func(md protoreflect.MessageDescriptor) {
			if md.IsMapEntry() || walkErr != nil {
				return
			}
			err := v.Validate(dynamicpb.NewMessage(md))
			var verr *protovalidate.ValidationError
			if err == nil || !errors.As(err, &verr) {
				walkErr = err
				return
			}
			for _, viol := range verr.Violations {
				elems := viol.Proto.GetField().GetElements()
				if len(elems) == 0 {
					continue // A message-level rule names no single field.
				}
				if f := md.Fields().ByName(protoreflect.Name(elems[0].GetFieldName())); f != nil {
					out[field{string(md.FullName()), f.JSONName()}] = true
				}
			}
		})
		return walkErr == nil
	})
	return out, walkErr
}

// Fix applies the corrections to a generated schema. Fields it is asked to
// constrain must exist when their message is in the schema, so a renamed
// field cannot silently lose its bound.
func Fix(doc []byte, facts Facts) ([]byte, error) {
	minimums := facts.Minimums
	root, err := parse(doc)
	if err != nil {
		return nil, err
	}
	schemas := root.get("components").get("schemas")
	if schemas == nil {
		return nil, errors.New("no components.schemas")
	}
	keys := make([]field, 0, len(minimums))
	for f := range minimums {
		keys = append(keys, f)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].schema != keys[j].schema {
			return keys[i].schema < keys[j].schema
		}
		return keys[i].property < keys[j].property
	})
	for _, f := range keys {
		s := schemas.get(f.schema)
		if s == nil {
			continue // Not part of the documented API surface.
		}
		p := s.get("properties").get(f.property)
		if p == nil {
			return nil, fmt.Errorf("%s has no property %q", f.schema, f.property)
		}
		if items := p.get("items"); p.get("type").scalar() == `"array"` && items != nil {
			p = items
		}
		if err := setMinimumZero(p); err != nil {
			return nil, fmt.Errorf("%s.%s: %w", f.schema, f.property, err)
		}
	}
	paths := root.get("paths")
	if paths != nil {
		for _, item := range paths.obj {
			for _, op := range item.value.obj {
				fixHeaders(op.value)
				if op.value.get("requestBody") == nil {
					continue
				}
				responses := op.value.get("responses")
				if responses == nil {
					return nil, errors.New("operation without responses")
				}
				if responses.get("415") == nil {
					responses.obj = append(responses.obj, member{"415", &node{obj: []member{{"description", &node{raw: quote(unsupportedMedia)}}}}})
				}
			}
		}
	}
	schemas.obj = slices.DeleteFunc(schemas.obj, func(m member) bool { return m.key == timeoutSchema })
	for _, name := range requestSchemas(paths, schemas) {
		props := schemas.get(name).get("properties")
		if props == nil {
			continue // An enum, a well-known type or a message without fields.
		}
		s := schemas.get(name)
		for _, prop := range props.obj {
			f := field{name, prop.key}
			if r, ok := facts.Enums[f]; ok {
				target := prop.value
				if items := target.get("items"); items != nil {
					target = items
				}
				restrictEnum(target, r)
			}
			if facts.ZeroInvalid[f] {
				require(s, prop.key)
				continue
			}
			if facts.Strings[f] {
				allowEmpty(prop.value)
			}
			acceptNull(prop.value)
			acceptNullEnum(prop.value) // Also on a rerun, after restrictEnum.
		}
	}
	var buf bytes.Buffer
	root.write(&buf, "")
	return buf.Bytes(), nil
}

// fixHeaders removes Connect-Timeout-Ms from an operation's parameters (and
// the parameters list when nothing else is left) and makes
// Connect-Protocol-Version optional.
func fixHeaders(op *node) {
	params := op.get("parameters")
	if params == nil {
		return
	}
	header := func(p *node, name string) bool {
		return p.get("in").scalar() == `"header"` && p.get("name").scalar() == string(quote(name))
	}
	params.arr = slices.DeleteFunc(params.arr, func(p *node) bool { return header(p, timeoutHeader) })
	for _, p := range params.arr {
		if header(p, versionHeader) {
			p.obj = slices.DeleteFunc(p.obj, func(m member) bool { return m.key == "required" })
		}
	}
	if len(params.arr) == 0 {
		op.obj = slices.DeleteFunc(op.obj, func(m member) bool { return m.key == "parameters" })
	}
}

// requestSchemas lists, sorted, the component schemas a request body can
// reach through $ref.
func requestSchemas(paths, schemas *node) []string {
	const prefix = "#/components/schemas/"
	seen := map[string]bool{}
	var walk func(n *node)
	walk = func(n *node) {
		if n == nil {
			return
		}
		for _, m := range n.obj {
			if m.key == "$ref" {
				var ref string
				if json.Unmarshal(m.value.raw, &ref) == nil && len(ref) > len(prefix) && ref[:len(prefix)] == prefix {
					if name := ref[len(prefix):]; !seen[name] {
						seen[name] = true
						walk(schemas.get(name))
					}
				}
				continue
			}
			walk(m.value)
		}
		for _, v := range n.arr {
			walk(v)
		}
	}
	if paths != nil {
		for _, item := range paths.obj {
			for _, op := range item.value.obj {
				walk(op.value.get("requestBody"))
			}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// restrictEnum states the rule by value name: `in` as an enum, `not_in` as
// a not-enum, replacing the generator's numeric not.
func restrictEnum(p *node, r EnumRule) {
	list := func(names []string) *node {
		n := &node{isArr: true}
		for _, name := range names {
			n.arr = append(n.arr, &node{raw: quote(name)})
		}
		return n
	}
	p.obj = slices.DeleteFunc(p.obj, func(m member) bool { return m.key == "not" || (m.key == "enum" && len(r.In) > 0) })
	if len(r.In) > 0 {
		p.obj = append(p.obj, member{"enum", list(r.In)})
	}
	if len(r.NotIn) > 0 {
		p.obj = append(p.obj, member{"not", &node{obj: []member{{"enum", list(r.NotIn)}}}})
	}
}

// require adds name to a schema's required list.
func require(s *node, name string) {
	req := s.get("required")
	if req == nil {
		req = &node{isArr: true}
		s.obj = append(s.obj, member{"required", req})
	}
	if !slices.ContainsFunc(req.arr, func(v *node) bool { return string(v.raw) == string(quote(name)) }) {
		req.arr = append(req.arr, &node{raw: quote(name)})
	}
}

// allowEmpty lets a string property also be "", moving the keywords that
// refuse it (pattern, format, minLength) into an anyOf branch.
func allowEmpty(p *node) {
	var moved []member
	p.obj = slices.DeleteFunc(p.obj, func(m member) bool {
		if m.key == "pattern" || m.key == "format" || (m.key == "minLength" && m.value.scalar() != "0") {
			moved = append(moved, m)
			return true
		}
		return false
	})
	if len(moved) == 0 {
		return
	}
	empty := &node{obj: []member{{"maxLength", &node{raw: []byte("0")}}}}
	p.obj = append(p.obj, member{"anyOf", &node{isArr: true, arr: []*node{{obj: moved}, empty}}})
}

// acceptNull lets a property schema also take null: a reference becomes
// anyOf [ref, null], a typed schema gains the null type (and null in its
// enum). It is idempotent.
func acceptNull(p *node) {
	nullType := &node{obj: []member{{"type", &node{raw: quote("null")}}}}
	for i, m := range p.obj {
		switch m.key {
		case "$ref":
			p.obj[i] = member{"anyOf", &node{isArr: true, arr: []*node{{obj: []member{m}}, nullType}}}
			acceptNullEnum(p)
			return
		case "type":
			if m.value.raw != nil {
				if string(m.value.raw) == `"null"` {
					return
				}
				p.obj[i].value = &node{isArr: true, arr: []*node{m.value, {raw: []byte(`"null"`)}}}
			} else if !slices.ContainsFunc(m.value.arr, func(v *node) bool { return string(v.raw) == `"null"` }) {
				m.value.arr = append(m.value.arr, &node{raw: []byte(`"null"`)})
			}
			acceptNullEnum(p)
			return
		}
	}
}

func acceptNullEnum(p *node) {
	if enum := p.get("enum"); enum != nil && !slices.ContainsFunc(enum.arr, func(v *node) bool { return string(v.raw) == "null" }) {
		enum.arr = append(enum.arr, &node{raw: []byte("null")})
	}
}

// setMinimumZero adds `minimum: 0` after `maximum` (or after `title`, else
// first), the place the generator uses for non-zero bounds.
func setMinimumZero(p *node) error {
	if p.raw != nil || p.arr != nil {
		return errors.New("not a schema object")
	}
	if m := p.get("minimum"); m != nil {
		if m.scalar() != "0" {
			return fmt.Errorf("minimum %s contradicts gte 0", m.scalar())
		}
		return nil
	}
	at := 0
	for i, m := range p.obj {
		if m.key == "maximum" || (m.key == "title" && at == 0) {
			at = i + 1
		}
	}
	p.obj = append(p.obj[:at], append([]member{{"minimum", &node{raw: []byte("0")}}}, p.obj[at:]...)...)
	return nil
}

// node is an order-preserving JSON value: an object, an array or a raw
// scalar exactly as encoded.
type node struct {
	obj []member
	arr []*node
	raw []byte
	// isObj and isArr tell empty containers from scalars.
	isObj, isArr bool
}

type member struct {
	key   string
	value *node
}

func (n *node) get(key string) *node {
	if n == nil {
		return nil
	}
	for _, m := range n.obj {
		if m.key == key {
			return m.value
		}
	}
	return nil
}

func (n *node) scalar() string {
	if n == nil {
		return ""
	}
	return string(n.raw)
}

func parse(doc []byte) (*node, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(doc))
	n, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.ReadToken(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the schema")
	}
	return n, nil
}

// parseValue keeps scalars as the exact bytes read, so rewriting the file
// changes nothing it did not mean to.
func parseValue(dec *jsontext.Decoder) (*node, error) {
	switch dec.PeekKind() { //nolint:exhaustive // Only containers are walked; every other kind is a raw value.
	case '{':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		n := &node{isObj: true}
		for dec.PeekKind() != '}' {
			k, err := dec.ReadToken()
			if err != nil {
				return nil, err
			}
			key := k.String() // The token is void after the next read.
			v, err := parseValue(dec)
			if err != nil {
				return nil, err
			}
			n.obj = append(n.obj, member{key, v})
		}
		_, err := dec.ReadToken()
		return n, err
	case '[':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		n := &node{isArr: true}
		for dec.PeekKind() != ']' {
			v, err := parseValue(dec)
			if err != nil {
				return nil, err
			}
			n.arr = append(n.arr, v)
		}
		_, err := dec.ReadToken()
		return n, err
	}
	v, err := dec.ReadValue()
	if err != nil {
		return nil, err
	}
	return &node{raw: bytes.Clone(v)}, nil
}

// quote encodes a string the way the generator writes the schema
// (encoding/json defaults, which escape <, > and &).
func quote(s string) []byte {
	b, err := json.Marshal(s, jsontext.EscapeForHTML(true))
	if err != nil {
		panic(err) // A string always encodes.
	}
	return b
}

// write matches json.MarshalIndent with a two-space indent and no trailing
// newline.
func (n *node) write(w *bytes.Buffer, indent string) {
	switch {
	case n.raw != nil:
		w.Write(n.raw)
	case n.isArr || n.arr != nil:
		if len(n.arr) == 0 {
			w.WriteString("[]")
			return
		}
		w.WriteString("[\n")
		for i, v := range n.arr {
			w.WriteString(indent + "  ")
			v.write(w, indent+"  ")
			if i < len(n.arr)-1 {
				w.WriteByte(',')
			}
			w.WriteByte('\n')
		}
		w.WriteString(indent + "]")
	default:
		if len(n.obj) == 0 {
			w.WriteString("{}")
			return
		}
		w.WriteString("{\n")
		for i, m := range n.obj {
			w.WriteString(indent + "  ")
			w.Write(quote(m.key))
			w.WriteString(": ")
			m.value.write(w, indent+"  ")
			if i < len(n.obj)-1 {
				w.WriteByte(',')
			}
			w.WriteByte('\n')
		}
		w.WriteString(indent + "}")
	}
}

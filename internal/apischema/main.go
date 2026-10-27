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
//   - a property of a request message also accepts null, which ProtoJSON
//     reads as the field's default, unless that default breaks the field's
//     own protovalidate rules (then null is refused like the default).
//
// It runs from `task api:schema` and rewrites the file in place, keeping the
// generator's key order and formatting so the nightly drift check still works.
//
//	go run ./internal/apischema docs/api/pantherclaw.openapi.json
package main

import (
	"bytes"
	"encoding/json"
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
	invalid, err := zeroInvalid(protoregistry.GlobalFiles)
	if err != nil {
		return err
	}
	out, err := Fix(in, zeroMinimums(protoregistry.GlobalFiles), invalid)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644) //nolint:gosec // A committed, world-readable document.
}

// field names one property of a component schema.
type field struct{ schema, property string }

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
// field cannot silently lose its bound. zeroInvalid names the request
// properties that must not accept null.
func Fix(doc []byte, minimums, zeroInvalid map[field]bool) ([]byte, error) {
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
		for _, prop := range props.obj {
			if !zeroInvalid[field{name, prop.key}] {
				acceptNull(prop.value)
			}
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

// acceptNull lets a property schema also take null: a reference becomes
// anyOf [ref, null], a typed schema gains the null type (and null in its
// enum). It is idempotent.
func acceptNull(p *node) {
	nullType := &node{obj: []member{{"type", &node{raw: quote("null")}}}}
	for i, m := range p.obj {
		switch m.key {
		case "$ref":
			p.obj[i] = member{"anyOf", &node{isArr: true, arr: []*node{{obj: []member{m}}, nullType}}}
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
			if enum := p.get("enum"); enum != nil && !slices.ContainsFunc(enum.arr, func(v *node) bool { return string(v.raw) == "null" }) {
				enum.arr = append(enum.arr, &node{raw: []byte("null")})
			}
			return
		}
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
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	n, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the schema")
	}
	return n, nil
}

func parseValue(dec *json.Decoder) (*node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			n := &node{isObj: true}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return nil, err
				}
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				n.obj = append(n.obj, member{k.(string), v})
			}
			_, err := dec.Token()
			return n, err
		case '[':
			n := &node{isArr: true}
			for dec.More() {
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				n.arr = append(n.arr, v)
			}
			_, err := dec.Token()
			return n, err
		}
		return nil, fmt.Errorf("unexpected %v", t)
	case string:
		return &node{raw: quote(t)}, nil
	case json.Number:
		return &node{raw: []byte(t)}, nil
	case bool:
		return &node{raw: []byte(fmt.Sprint(t))}, nil
	case nil:
		return &node{raw: []byte("null")}, nil
	}
	return nil, fmt.Errorf("unexpected token %v", tok)
}

// quote encodes a string the way encoding/json does by default, which is
// how the generator writes the schema.
func quote(s string) []byte {
	b, _ := json.Marshal(s) //nolint:errchkjson // A string always encodes.
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

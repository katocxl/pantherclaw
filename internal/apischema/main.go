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
//     (504), which is not a property of the operation.
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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	_ "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1" // Registers the API descriptors.
)

const (
	// unsupportedMedia is the response Connect sends without a body.
	unsupportedMedia = "Unsupported media type, no body"
	// timeoutHeader and its component are left out of the schema.
	timeoutHeader, timeoutSchema = "Connect-Timeout-Ms", "connect-timeout-header"
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
	out, err := Fix(in, zeroMinimums(protoregistry.GlobalFiles))
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

// Fix applies both corrections to a generated schema. Fields it is asked to
// constrain must exist when their message is in the schema, so a renamed
// field cannot silently lose its bound.
func Fix(doc []byte, minimums map[field]bool) ([]byte, error) {
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
				dropTimeoutHeader(op.value)
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
	var buf bytes.Buffer
	root.write(&buf, "")
	return buf.Bytes(), nil
}

// dropTimeoutHeader removes Connect-Timeout-Ms from an operation's
// parameters, and the parameters list when nothing else is left.
func dropTimeoutHeader(op *node) {
	params := op.get("parameters")
	if params == nil {
		return
	}
	params.arr = slices.DeleteFunc(params.arr, func(p *node) bool {
		return p.get("in").scalar() == `"header"` && p.get("name").scalar() == string(quote(timeoutHeader))
	})
	if len(params.arr) == 0 {
		op.obj = slices.DeleteFunc(op.obj, func(m member) bool { return m.key == "parameters" })
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

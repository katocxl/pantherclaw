// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"io"
	"strconv"
)

// Prompt capture without images (G0 M33 D985, HR-757): before a model
// request body is kept as a capture, every image, document or screenshot
// block in it is replaced by
// {"type":"<original>","omitted":true,"bytes":N,"sha256":"<hex>"}, N and
// the digest those of the block's raw JSON, and the text is kept. A body
// that cannot be parsed is not kept: its capture says omitted.

// omittedTypes are the block types a capture never keeps: Anthropic image
// and document blocks (at any depth, tool_result content included), Chat
// image_url parts, and Responses input_image and input_file items.
var omittedTypes = map[string]bool{"image": true, "document": true, "image_url": true, "input_image": true, "input_file": true}

// computerOutputType is the Responses item whose output (a screenshot) is
// never kept.
const computerOutputType = "computer_call_output"

// withoutImages returns body with every omitted block replaced, or false
// when body is not one JSON value.
func withoutImages(body []byte) ([]byte, bool) {
	dec := jsontext.NewDecoder(bytes.NewReader(body))
	v, err := dec.ReadValue()
	if err != nil {
		return nil, false
	}
	if _, err := dec.ReadToken(); err != io.EOF {
		return nil, false
	}
	out, err := omitBlocks(v)
	if err != nil {
		return nil, false
	}
	return out, true
}

// omittedBody is what a capture keeps of a body it cannot parse.
func omittedBody(size int) []byte {
	return []byte(`{"omitted":true,"bytes":` + strconv.Itoa(size) + `}`)
}

type member struct {
	name  string
	value jsontext.Value
}

// placeholder is the omitted form of raw, a block of type typ.
func placeholder(typ string, raw jsontext.Value) (jsontext.Value, error) {
	sum := sha256.Sum256(raw)
	var buf bytes.Buffer
	enc := jsontext.NewEncoder(&buf)
	for _, t := range []jsontext.Token{
		jsontext.BeginObject,
		jsontext.String("type"), jsontext.String(typ),
		jsontext.String("omitted"), jsontext.True,
		jsontext.String("bytes"), jsontext.Int(int64(len(raw))),
		jsontext.String("sha256"), jsontext.String(hex.EncodeToString(sum[:])),
		jsontext.EndObject,
	} {
		if err := enc.WriteToken(t); err != nil {
			return nil, err
		}
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

// members reads an object's members in order.
func members(v jsontext.Value) ([]member, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(v))
	if _, err := dec.ReadToken(); err != nil {
		return nil, err
	}
	var out []member
	for dec.PeekKind() != '}' {
		name, err := dec.ReadToken()
		if err != nil {
			return nil, err
		}
		val, err := dec.ReadValue()
		if err != nil {
			return nil, err
		}
		out = append(out, member{name: name.String(), value: append(jsontext.Value(nil), val...)})
	}
	return out, nil
}

// typeOf is an object's "type" member when it is a string.
func typeOf(ms []member) string {
	for _, m := range ms {
		if m.name == "type" && m.value.Kind() == '"' {
			dec := jsontext.NewDecoder(bytes.NewReader(m.value))
			if t, err := dec.ReadToken(); err == nil {
				return t.String()
			}
		}
	}
	return ""
}

func omitBlocks(v jsontext.Value) (jsontext.Value, error) {
	switch v.Kind() {
	case '{':
		ms, err := members(v)
		if err != nil {
			return nil, err
		}
		typ := typeOf(ms)
		if omittedTypes[typ] {
			return placeholder(typ, v)
		}
		for i := range ms {
			if typ == computerOutputType && ms[i].name == "output" {
				inner := "output"
				if ms[i].value.Kind() == '{' {
					sub, err := members(ms[i].value)
					if err != nil {
						return nil, err
					}
					if t := typeOf(sub); t != "" {
						inner = t
					}
				}
				if ms[i].value, err = placeholder(inner, ms[i].value); err != nil {
					return nil, err
				}
				continue
			}
			if ms[i].value, err = omitBlocks(ms[i].value); err != nil {
				return nil, err
			}
		}
		var buf bytes.Buffer
		enc := jsontext.NewEncoder(&buf)
		if err := enc.WriteToken(jsontext.BeginObject); err != nil {
			return nil, err
		}
		for _, m := range ms {
			if err := enc.WriteToken(jsontext.String(m.name)); err != nil {
				return nil, err
			}
			if err := enc.WriteValue(m.value); err != nil {
				return nil, err
			}
		}
		if err := enc.WriteToken(jsontext.EndObject); err != nil {
			return nil, err
		}
		return bytes.TrimSpace(buf.Bytes()), nil
	case '[':
		dec := jsontext.NewDecoder(bytes.NewReader(v))
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		enc := jsontext.NewEncoder(&buf)
		if err := enc.WriteToken(jsontext.BeginArray); err != nil {
			return nil, err
		}
		for dec.PeekKind() != ']' {
			el, err := dec.ReadValue()
			if err != nil {
				return nil, err
			}
			out, err := omitBlocks(append(jsontext.Value(nil), el...))
			if err != nil {
				return nil, err
			}
			if err := enc.WriteValue(out); err != nil {
				return nil, err
			}
		}
		if err := enc.WriteToken(jsontext.EndArray); err != nil {
			return nil, err
		}
		return bytes.TrimSpace(buf.Bytes()), nil
	default:
		return v, nil
	}
}

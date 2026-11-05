// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

func ambiguous(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{actionir.ErrAmbiguous}, args...)...)
}

var integer = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,18})$`)

// DecodeInput strictly decodes a tool call's JSON object (MCP arguments or
// an HTTP body) into CEL-ready values (HR-100): duplicate keys, invalid
// UTF-8, depth beyond actionir.MaxDepth, size beyond actionir.MaxBytes and
// any non-integer number are ambiguous. Integers become int64; there are no
// floats, so an amount sent as a number can never become money (HR-101).
func DecodeInput(raw []byte) (map[string]any, error) {
	return decodeInput(raw, nil)
}

// decodeInput is DecodeInput where floats names the top-level fields the
// mapping extracts into a float_array param (G0 M30 D1211): only there is
// a list of numbers read, and it becomes the param's canonical string
// (domain.EncodeFloat32s). HR-101 covers material params, and a
// float_array is never material; every other number stays an integer or
// is refused.
func decodeInput(raw []byte, floats map[string]bool) (map[string]any, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, nil
	}
	if len(raw) > actionir.MaxBytes {
		return nil, ambiguous("input larger than %d bytes", actionir.MaxBytes)
	}
	d := jsontext.NewDecoder(bytes.NewReader(raw))
	var v any
	var err error
	if len(floats) > 0 && d.PeekKind() == '{' {
		v, err = decodeTop(d, floats)
	} else {
		v, err = decodeValue(d)
	}
	if err != nil {
		return nil, err
	}
	if _, err := d.ReadToken(); !errors.Is(err, io.EOF) {
		return nil, ambiguous("trailing data after the input object")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, ambiguous("input must be a JSON object")
	}
	return obj, nil
}

func decodeValue(d *jsontext.Decoder) (any, error) {
	tok, err := d.ReadToken()
	if err != nil {
		return nil, ambiguous("input: %v", err)
	}
	if d.StackDepth() > actionir.MaxDepth {
		return nil, ambiguous("input nested deeper than %d", actionir.MaxDepth)
	}
	switch tok.Kind() {
	case jsontext.KindBeginObject:
		obj := map[string]any{}
		for d.PeekKind() != '}' {
			k, err := d.ReadToken()
			if err != nil {
				return nil, ambiguous("input: %v", err)
			}
			name := k.String() // copy before the next read voids the token
			v, err := decodeValue(d)
			if err != nil {
				return nil, err
			}
			obj[name] = v
		}
		_, err = d.ReadToken()
		return obj, wrap(err)
	case jsontext.KindBeginArray:
		arr := []any{}
		for d.PeekKind() != ']' {
			v, err := decodeValue(d)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		_, err = d.ReadToken()
		return arr, wrap(err)
	case jsontext.KindString:
		return tok.String(), nil
	case jsontext.KindNumber:
		s := tok.String()
		n, err := strconv.ParseInt(s, 10, 64)
		if !integer.MatchString(s) || err != nil {
			return nil, ambiguous("input number %.24q is not an integer; send amounts as decimal strings (HR-101)", s)
		}
		return n, nil
	case jsontext.KindTrue, jsontext.KindFalse:
		return tok.Bool(), nil
	case jsontext.KindNull:
		return nil, nil
	case jsontext.KindInvalid, jsontext.KindEndObject, jsontext.KindEndArray:
		return nil, ambiguous("input: unexpected %v", tok.Kind())
	}
	return nil, ambiguous("input: unexpected %v", tok.Kind())
}

// decodeTop decodes the input object, reading the fields in floats as
// float arrays.
func decodeTop(d *jsontext.Decoder, floats map[string]bool) (map[string]any, error) {
	if _, err := d.ReadToken(); err != nil {
		return nil, ambiguous("input: %v", err)
	}
	obj := map[string]any{}
	for d.PeekKind() != '}' {
		k, err := d.ReadToken()
		if err != nil {
			return nil, ambiguous("input: %v", err)
		}
		name := k.String()
		var v any
		if floats[name] {
			v, err = decodeFloatArray(d, name)
		} else {
			v, err = decodeValue(d)
		}
		if err != nil {
			return nil, err
		}
		obj[name] = v
	}
	_, err := d.ReadToken()
	return obj, wrap(err)
}

// decodeFloatArray reads a list of 1..MaxFloatItems JSON numbers, each
// finite and within float32 range, as its canonical string. Anything else
// at that field is ambiguous.
func decodeFloatArray(d *jsontext.Decoder, name string) (string, error) {
	tok, err := d.ReadToken()
	if err != nil {
		return "", ambiguous("input: %v", err)
	}
	if tok.Kind() != '[' {
		return "", ambiguous("input %s must be a list of numbers", name)
	}
	var fs []float64
	for d.PeekKind() != ']' {
		tok, err := d.ReadToken()
		if err != nil {
			return "", ambiguous("input: %v", err)
		}
		if tok.Kind() != '0' || len(fs) == domain.MaxFloatItems {
			return "", ambiguous("input %s must be a list of at most %d numbers", name, domain.MaxFloatItems)
		}
		f, err := strconv.ParseFloat(tok.String(), 64)
		if err != nil {
			return "", ambiguous("input %s: a number out of range", name)
		}
		fs = append(fs, f)
	}
	if _, err := d.ReadToken(); err != nil {
		return "", ambiguous("input: %v", err)
	}
	s, err := domain.EncodeFloat32s(fs)
	if err != nil {
		return "", ambiguous("input %s: %v", name, err)
	}
	return s, nil
}

func wrap(err error) error {
	if err != nil {
		return ambiguous("input: %v", err)
	}
	return nil
}

// segment is one segment of a reviewed path template. A rest segment, the
// last one written {name*}, takes one or more segments, joined with "/".
type segment struct {
	literal string
	param   string
	rest    bool
}

func parseTemplate(t string) []segment {
	parts := strings.Split(t[1:], "/")
	out := make([]segment, len(parts))
	for i, p := range parts {
		if name, ok := strings.CutSuffix(strings.TrimPrefix(p, "{"), "*}"); ok && strings.HasPrefix(p, "{") {
			out[i] = segment{param: name, rest: true}
		} else if strings.HasPrefix(p, "{") {
			out[i] = segment{param: p[1 : len(p)-1]}
		} else {
			out[i] = segment{literal: p}
		}
	}
	return out
}

var pathChars = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// matchPath matches a raw request path against a template. The raw path is
// compared byte for byte: percent-encodings, dot segments, empty segments
// and characters outside the unreserved set never match, so no decoding
// differential can reach a target (HR-073 groundwork).
func matchPath(tmpl []segment, raw string) (map[string]any, bool) {
	if !strings.HasPrefix(raw, "/") {
		return nil, false
	}
	if isRoot(tmpl) {
		return map[string]any{}, raw == "/" // the service root (G0 M20 D254)
	}
	parts := strings.Split(raw[1:], "/")
	rest := len(tmpl) > 0 && tmpl[len(tmpl)-1].rest
	if len(parts) != len(tmpl) && (!rest || len(parts) < len(tmpl)) {
		return nil, false
	}
	vars := map[string]any{}
	for i, p := range parts {
		if !pathChars.MatchString(p) || p == "." || p == ".." {
			return nil, false
		}
		switch {
		case i >= len(tmpl)-1 && rest:
			vars[tmpl[len(tmpl)-1].param] = strings.Join(parts[len(tmpl)-1:], "/")
		case tmpl[i].param != "":
			vars[tmpl[i].param] = p
		case tmpl[i].literal != p:
			return nil, false
		}
	}
	return vars, true
}

// parseQuery parses a query string; a repeated key is ambiguous.
func parseQuery(raw string) (map[string]any, error) {
	q, err := url.ParseQuery(raw)
	if err != nil {
		return nil, ambiguous("query: %v", err)
	}
	out := make(map[string]any, len(q))
	for k, vs := range q {
		if len(vs) != 1 {
			return nil, ambiguous("query parameter %q is repeated", k)
		}
		out[k] = vs[0]
	}
	return out, nil
}

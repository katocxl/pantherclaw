// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"regexp"
)

// refPattern matches a well-formed ${name} reference. There are no
// expressions: a reference is a saved value's name or fixture.<name>.
var refPattern = regexp.MustCompile(`\$\{([a-z][a-z0-9_]{0,31}|fixture\.[a-z][a-z0-9_]{0,31})\}`)

// MapStrings rewrites every string value (never an object key) of a JSON
// value with fn, keeping numbers and structure byte for byte. A key that
// contains "${" is an error: substitution applies to values only.
func MapStrings(v []byte, fn func(string) (string, error)) ([]byte, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(v))
	var out bytes.Buffer
	enc := jsontext.NewEncoder(&out)
	type frame struct {
		obj bool
		n   int
	}
	var stack []frame
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, invalid("%v", err)
		}
		k := tok.Kind()
		if k == '}' || k == ']' {
			stack = stack[:len(stack)-1]
			if err := enc.WriteToken(tok); err != nil {
				return nil, invalid("%v", err)
			}
			continue
		}
		isKey := false
		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			isKey = top.obj && top.n%2 == 0
			top.n++
		}
		switch {
		case k == '"' && isKey:
			if bytes.Contains([]byte(tok.String()), []byte("${")) {
				return nil, invalid("object keys cannot hold a ${} reference")
			}
		case k == '"':
			s, err := fn(tok.String())
			if err != nil {
				return nil, err
			}
			tok = jsontext.String(s)
		case k == '{':
			stack = append(stack, frame{obj: true})
		case k == '[':
			stack = append(stack, frame{})
		}
		if err := enc.WriteToken(tok); err != nil {
			return nil, invalid("%v", err)
		}
	}
	return bytes.TrimSpace(out.Bytes()), nil
}

// References returns the names of every ${name} reference in the string
// values of a JSON value, and an error for a "${" that is not a well-formed
// reference.
func References(v []byte) ([]string, error) {
	var names []string
	_, err := MapStrings(v, func(s string) (string, error) {
		for _, m := range refPattern.FindAllStringSubmatch(s, -1) {
			names = append(names, m[1])
		}
		if rest := refPattern.ReplaceAllString(s, ""); bytes.Contains([]byte(rest), []byte("${")) {
			return "", invalid("malformed ${} reference in %q", truncate(s))
		}
		return s, nil
	})
	return names, err
}

// Substitute replaces each ${name} in the string values of a JSON value with
// vars[name] by plain, single-pass string replacement. An unknown name is an
// error.
func Substitute(v []byte, vars map[string]string) ([]byte, error) {
	return MapStrings(v, func(s string) (string, error) {
		var missing string
		out := refPattern.ReplaceAllStringFunc(s, func(m string) string {
			name := m[2 : len(m)-1]
			val, ok := vars[name]
			if !ok {
				missing = name
			}
			return val
		})
		if missing != "" {
			return "", fmt.Errorf("redteam: no value for ${%s}", missing)
		}
		return out, nil
	})
}

// jsonDepth returns the nesting depth of a JSON value (a scalar is 0).
func jsonDepth(v []byte) (int, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(v))
	depth, deepest := 0, 0
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			return deepest, nil
		}
		if err != nil {
			return 0, invalid("%v", err)
		}
		switch tok.Kind() { //nolint:exhaustive // only containers change the depth
		case '{', '[':
			depth++
			if depth > deepest {
				deepest = depth
			}
		case '}', ']':
			depth--
		default:
		}
	}
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package jsonptr reads one value out of a JSON document with an RFC 6901
// JSON Pointer (G0 M11 part 2 D2: an inbound parameter's "from"). It
// streams the document and returns the raw value; turning it into a typed,
// bounded parameter is the caller's job (HR-276).
package jsonptr

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Limits.
const (
	// MaxLen bounds a pointer's text.
	MaxLen = 256
	// MaxTokens bounds a pointer's depth.
	MaxTokens = 32
	// maxIndexDigits bounds an array index.
	maxIndexDigits = 6
)

// Errors.
var (
	ErrPointer  = errors.New("jsonptr: not a JSON Pointer (RFC 6901)")
	ErrDocument = errors.New("jsonptr: the document is not valid JSON")
	ErrNotFound = errors.New("jsonptr: nothing at that pointer")
)

// Pointer is a parsed JSON Pointer: its reference tokens, unescaped.
type Pointer struct {
	text   string
	tokens []string
}

// Parse parses a pointer. "" is the whole document; otherwise it starts
// with "/", and "~" appears only as "~0" (~) or "~1" (/).
func Parse(s string) (Pointer, error) {
	if len(s) > MaxLen {
		return Pointer{}, fmt.Errorf("%w: longer than %d characters", ErrPointer, MaxLen)
	}
	if s == "" {
		return Pointer{}, nil
	}
	if s[0] != '/' {
		return Pointer{}, fmt.Errorf("%w: %q does not start with /", ErrPointer, s)
	}
	raw := strings.Split(s[1:], "/")
	if len(raw) > MaxTokens {
		return Pointer{}, fmt.Errorf("%w: deeper than %d", ErrPointer, MaxTokens)
	}
	toks := make([]string, len(raw))
	for i, r := range raw {
		var b strings.Builder
		for j := 0; j < len(r); j++ {
			if r[j] != '~' {
				b.WriteByte(r[j])
				continue
			}
			if j+1 >= len(r) || (r[j+1] != '0' && r[j+1] != '1') {
				return Pointer{}, fmt.Errorf("%w: %q has a bad ~ escape", ErrPointer, s)
			}
			if r[j+1] == '0' {
				b.WriteByte('~')
			} else {
				b.WriteByte('/')
			}
			j++
		}
		toks[i] = b.String()
	}
	return Pointer{text: s, tokens: toks}, nil
}

// MustParse parses a pointer known to be valid.
func MustParse(s string) Pointer {
	p, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return p
}

// String returns the pointer as written.
func (p Pointer) String() string { return p.text }

// Tokens returns the unescaped reference tokens.
func (p Pointer) Tokens() []string { return append([]string(nil), p.tokens...) }

// Lookup returns a copy of the raw JSON value the pointer names. The whole
// document must be valid JSON (RFC 7493: UTF-8, unique names), so a value
// can never be read from an ambiguous document.
func (p Pointer) Lookup(doc []byte) (jsontext.Value, error) {
	if !jsontext.Value(doc).IsValid() {
		return nil, ErrDocument
	}
	d := jsontext.NewDecoder(bytes.NewReader(doc))
	for _, tok := range p.tokens {
		if err := descend(d, tok); err != nil {
			return nil, err
		}
	}
	v, err := d.ReadValue()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDocument, err)
	}
	return bytes.Clone(v), nil
}

// descend moves d to the start of member tok of the next value.
func descend(d *jsontext.Decoder, tok string) error {
	switch d.PeekKind() { //nolint:exhaustive // only containers have members
	case '{':
		if _, err := d.ReadToken(); err != nil {
			return fmt.Errorf("%w: %w", ErrDocument, err)
		}
		for d.PeekKind() != '}' {
			name, err := d.ReadToken()
			if err != nil {
				return fmt.Errorf("%w: %w", ErrDocument, err)
			}
			if name.String() == tok {
				return nil
			}
			if err := d.SkipValue(); err != nil {
				return fmt.Errorf("%w: %w", ErrDocument, err)
			}
		}
		return ErrNotFound
	case '[':
		n, ok := index(tok)
		if !ok {
			return ErrNotFound
		}
		if _, err := d.ReadToken(); err != nil {
			return fmt.Errorf("%w: %w", ErrDocument, err)
		}
		for i := 0; d.PeekKind() != ']'; i++ {
			if i == n {
				return nil
			}
			if err := d.SkipValue(); err != nil {
				return fmt.Errorf("%w: %w", ErrDocument, err)
			}
		}
		return ErrNotFound
	default:
		return ErrNotFound
	}
}

// index reads an array index: "0" or digits without a leading zero. "-"
// (past the end) names nothing to read.
func index(tok string) (int, bool) {
	if tok == "" || len(tok) > maxIndexDigits || (len(tok) > 1 && tok[0] == '0') {
		return 0, false
	}
	for _, c := range []byte(tok) {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(tok)
	return n, err == nil
}

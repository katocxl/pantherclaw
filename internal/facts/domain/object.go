// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"io"
	"strconv"
)

// Object facts (G0 M8): one read of a system of record is one fact with
// several members, such as a pull request's head ({"sha": …, "base": …}).
// A value is a JSON object of strings, integers, booleans, arrays and
// objects; never floats or nulls, at most maxObjectDepth deep and
// maxObjectBytes long. Policies and consequence rules read it as
// map(string, dyn): facts.github_pull_head.sha.
const (
	TypeObject     Type = "object"
	maxObjectBytes      = 16 << 10
	maxObjectDepth      = 4
)

// UnknownMember is the member an object fact carries when the provider
// read it but could not evaluate it: a consequence that needs the fact is
// then UNKNOWN, with this member's text as the reason (HR-206).
const UnknownMember = "unknown"

// UnreadMember is the member an object fact carries when its provider
// could not read it (a failed read of the system of record): the fact
// counts as missing, so a prerequisite is CANNOT_AUTHORIZE and a consequence
// that needs it is UNKNOWN, and an older observation never stands in for
// it (the coordinator's decision Q11, #308 review).
const UnreadMember = "unread"

// Unread is why an object fact was not read, when it carries UnreadMember.
func (v Value) Unread() (string, bool) {
	if v.Type != TypeObject {
		return "", false
	}
	why, ok := v.Object[UnreadMember]
	if !ok {
		return "", false
	}
	s, _ := why.(string)
	return s, true
}

// decodeObject strictly decodes an object fact's members.
func decodeObject(raw jsontext.Value) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > maxObjectBytes {
		return nil, invalid("value: an object of %d bytes, at most %d", len(raw), maxObjectBytes)
	}
	d := jsontext.NewDecoder(bytes.NewReader(raw))
	v, err := decodeMember(d)
	if err != nil {
		return nil, err
	}
	if _, err := d.ReadToken(); !errors.Is(err, io.EOF) {
		return nil, invalid("value: trailing data after the object")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, invalid("value: an object fact is a JSON object")
	}
	return obj, nil
}

func decodeMember(d *jsontext.Decoder) (any, error) {
	tok, err := d.ReadToken()
	if err != nil {
		return nil, invalid("value: %v", err)
	}
	if d.StackDepth() > maxObjectDepth {
		return nil, invalid("value: nested deeper than %d", maxObjectDepth)
	}
	switch tok.Kind() {
	case jsontext.KindBeginObject:
		obj := map[string]any{}
		for d.PeekKind() != '}' {
			k, err := d.ReadToken()
			if err != nil {
				return nil, invalid("value: %v", err)
			}
			name := k.String()
			if obj[name], err = decodeMember(d); err != nil {
				return nil, err
			}
		}
		_, err := d.ReadToken()
		return obj, wrapValue(err)
	case jsontext.KindBeginArray:
		arr := []any{}
		for d.PeekKind() != ']' {
			v, err := decodeMember(d)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		_, err := d.ReadToken()
		return arr, wrapValue(err)
	case jsontext.KindString:
		return tok.String(), nil
	case jsontext.KindNumber:
		s := tok.String()
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || !intPattern.MatchString(s) {
			return nil, invalid("value: %.24q is not an integer", s)
		}
		return n, nil
	case jsontext.KindTrue, jsontext.KindFalse:
		return tok.Bool(), nil
	case jsontext.KindNull, jsontext.KindInvalid, jsontext.KindEndObject, jsontext.KindEndArray:
	}
	return nil, invalid("value: %v is not allowed in an object fact", tok.Kind())
}

func wrapValue(err error) error {
	if err != nil {
		return invalid("value: %v", err)
	}
	return nil
}

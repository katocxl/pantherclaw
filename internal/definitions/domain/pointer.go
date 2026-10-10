// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strconv"
	"strings"
)

// PointerValue reads the scalar at a package's JSON pointer (ValidPointer)
// in a JSON document, as the text a target reports: a string without its
// quotes, a number or a boolean as written. It returns false for anything
// else: no such member or index, an object, an array, null, duplicate
// member names or invalid JSON. It reads what a verifier declares and
// nothing more (HR-190).
func PointerValue(doc []byte, ptr string) (string, bool) {
	if !ValidPointer(ptr) {
		return "", false
	}
	v := jsontext.Value(doc)
	for _, tok := range strings.Split(ptr[1:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		next, ok := member(v, tok)
		if !ok {
			return "", false
		}
		v = next
	}
	if k := v.Kind(); k == jsontext.KindString {
		var s string
		if json.Unmarshal(v, &s) != nil {
			return "", false
		}
		return s, true
	} else if (k == jsontext.KindNumber || k == jsontext.KindTrue || k == jsontext.KindFalse) && v.IsValid() {
		return string(v), true
	}
	return "", false
}

// PointerItems reads the array at a package's JSON pointer (a listing's
// items), at most limit elements; it returns false for anything that is
// not an array there, or for more than limit elements.
func PointerItems(doc []byte, ptr string, limit int) ([]jsontext.Value, bool) {
	if !ValidPointer(ptr) {
		return nil, false
	}
	v := jsontext.Value(doc)
	for _, tok := range strings.Split(ptr[1:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		next, ok := member(v, tok)
		if !ok {
			return nil, false
		}
		v = next
	}
	var a []jsontext.Value
	if v.Kind() != jsontext.KindBeginArray || json.Unmarshal(v, &a) != nil || len(a) > limit {
		return nil, false
	}
	return a, true
}

// member returns the member tok of an object, or the element at index tok
// of an array (decimal, no leading zero); anything else is absent.
func member(v jsontext.Value, tok string) (jsontext.Value, bool) {
	if v.Kind() == jsontext.KindBeginObject {
		var m map[string]jsontext.Value
		if json.Unmarshal(v, &m) != nil {
			return nil, false
		}
		next, ok := m[tok]
		return next, ok
	}
	if v.Kind() != jsontext.KindBeginArray {
		return nil, false
	}
	var a []jsontext.Value
	i, err := strconv.Atoi(tok)
	if err != nil || json.Unmarshal(v, &a) != nil || i < 0 || i >= len(a) || (len(tok) > 1 && tok[0] == '0') {
		return nil, false
	}
	return a[i], true
}

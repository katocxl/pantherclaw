// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"encoding/json/jsontext"
	"slices"
	"unicode/utf8"
)

// BodyShingles are the shingles of a scanned body (D1104): of each string
// of a JSON body, so a shingle never spans two strings, or of the whole body
// when it is not JSON. Keys are left out. At most MaxTextShingles are made.
// Nothing about the body is kept.
func BodyShingles(body []byte) []string {
	var out []string
	add := func(s string) bool {
		out = append(out, Shingles(s)...)
		return len(out) < MaxTextShingles
	}
	dec := jsontext.NewDecoder(bytes.NewReader(body))
	if k := dec.PeekKind(); k != '{' && k != '[' {
		if utf8.Valid(body) {
			add(string(body))
		}
		return compactShingles(out)
	}
	for {
		tok, err := dec.ReadToken()
		if err != nil {
			break
		}
		if tok.Kind() != '"' {
			continue
		}
		// An object's keys alternate with its values; only values are text.
		if isKey(dec) {
			continue
		}
		if !add(tok.String()) {
			break
		}
	}
	return compactShingles(out)
}

// isKey reports whether the string token just read is an object key.
func isKey(dec *jsontext.Decoder) bool {
	k, n := dec.StackIndex(dec.StackDepth())
	return k == '{' && n%2 == 1
}

func compactShingles(in []string) []string {
	if len(in) > MaxTextShingles {
		in = in[:MaxTextShingles]
	}
	slices.Sort(in)
	return slices.Compact(in)
}

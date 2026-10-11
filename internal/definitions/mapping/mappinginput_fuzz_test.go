// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// onlyInputValues reports whether v holds only what strict decoding
// produces: objects, arrays, strings, int64, booleans and null.
func onlyInputValues(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for _, e := range x {
			if !onlyInputValues(e) {
				return false
			}
		}
	case []any:
		for _, e := range x {
			if !onlyInputValues(e) {
				return false
			}
		}
	case string, int64, bool, nil:
	default:
		return false
	}
	return true
}

// unreserved reports whether r may appear in a raw path a route matches:
// a separator or an RFC 3986 unreserved character.
func unreserved(r rune) bool {
	return r == '/' || r == '.' || r == '_' || r == '~' || r == '-' || 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9'
}

// FuzzMappingInput (G0 M4, HR-100, HR-101): no raw tool call input, HTTP
// method, raw path or raw query panics the mapper. Strict decoding accepts
// only one valid JSON object (no duplicate names, invalid UTF-8 or
// non-integer number) into objects, arrays, strings, int64, booleans and
// null, and its re-encoding decodes to the same value; what it refuses is
// ambiguous. A request the HTTP mapping accepts names exactly one reviewed
// route by a raw path of unreserved characters, with no repeated query
// parameter, and yields a canonical ActionIR that round-trips.
func FuzzMappingInput(f *testing.F) {
	m := mapperFor(f, mockRaw(f))
	f.Add(true, "/v1/refunds", "", []byte(refundArgs))
	f.Add(false, "/v1/refunds/re_0192-ab", "", []byte(nil))
	f.Add(false, "/v1/refunds/re_%31", "", []byte(nil))
	f.Add(false, "/v1/refunds/./re_1", "", []byte(nil))
	f.Add(true, "/v1/refunds", "x=1", []byte(refundArgs))
	f.Add(true, "/v1/refunds", "", []byte(`{"charge":"ch_1","charge":"ch_2","amount":"30","currency":"USD","reason":"duplicate"}`))
	f.Add(true, "/v1/refunds", "", []byte(`{"charge":"ch_1","amount":30.5,"currency":"USD","reason":"duplicate"}`))
	f.Add(true, "/v1/refunds", "", []byte(`{"charge":"ch_1","amount":"30","currency":"USD","reason":"duplicate"} {}`))
	f.Add(true, "/v1/refunds", "", []byte("{\"charge\":\"ch_\xff\"}"))
	f.Add(true, "/v1/refunds", "", []byte(strings.Repeat(`{"a":`, actionir.MaxDepth+1)+"1"+strings.Repeat("}", actionir.MaxDepth+1)))
	f.Add(true, "/v1/refunds", "", []byte(`{"n":-0,"m":9223372036854775808,"l":[1,"x",true,null,{"k":[]}]}`))
	f.Fuzz(func(t *testing.T, post bool, rawPath, rawQuery string, body []byte) {
		in, err := DecodeInput(body)
		if err != nil {
			if !errors.Is(err, actionir.ErrAmbiguous) {
				t.Fatalf("a refusal outside ErrAmbiguous: %v", err)
			}
		} else {
			if len(bytes.TrimSpace(body)) > 0 && !jsontext.Value(body).IsValid() {
				t.Fatalf("accepted input that is not one valid JSON value: %q", body)
			}
			if !onlyInputValues(any(in)) {
				t.Fatalf("decoded %q into %#v", body, in)
			}
			re, err := json.Marshal(in, json.Deterministic(true))
			if err != nil {
				t.Fatalf("decoded input does not encode: %v", err)
			}
			again, err := DecodeInput(re)
			if err != nil || !reflect.DeepEqual(again, in) {
				t.Fatalf("decoded input does not round-trip: %q → %q (%v)", body, re, err)
			}
		}
		method := "GET"
		if post {
			method = "POST"
		}
		p, merr := m.HTTP(context.Background(), tc, method, rawPath, rawQuery, body)
		if merr != nil {
			if !errors.Is(merr, actionir.ErrAmbiguous) && !errors.Is(merr, ErrUnmapped) {
				t.Fatalf("a refusal outside ErrAmbiguous and ErrUnmapped: %v", merr)
			}
			return
		}
		if err != nil {
			t.Fatalf("mapped a request whose body strict decoding refuses: %q", body)
		}
		route, ok := m.HTTPRoute(method, rawPath)
		if !ok || route != p.Action.Route || strings.ContainsFunc(rawPath, func(r rune) bool { return !unreserved(r) }) {
			t.Fatalf("%s %q mapped to route %q (route of the path: %q, %v)", method, rawPath, p.Action.Route, route, ok)
		}
		if q, err := parseQuery(rawQuery); err != nil || len(q) > 0 {
			t.Fatalf("mapped a request with the query %q, which no route reads (%v)", rawQuery, err)
		}
		re, err := actionir.Parse(p.Canonical)
		if err != nil || re.Hash != p.Hash || !bytes.Equal(re.Canonical, p.Canonical) {
			t.Fatalf("canonical ActionIR does not round-trip: %v\n%s", err, p.Canonical)
		}
	})
}

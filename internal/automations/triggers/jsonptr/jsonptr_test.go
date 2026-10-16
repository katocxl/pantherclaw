// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package jsonptr

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// The RFC 6901 §5 example document.
const rfcDoc = `{
  "foo": ["bar", "baz"],
  "": 0,
  "a/b": 1,
  "c%d": 2,
  "e^f": 3,
  "g|h": 4,
  "i\\j": 5,
  "k\"l": 6,
  " ": 7,
  "m~n": 8
}`

func TestRFC6901Examples(t *testing.T) {
	t.Parallel()
	for ptr, want := range map[string]string{
		"/foo":   `["bar", "baz"]`,
		"/foo/0": `"bar"`,
		"/foo/1": `"baz"`,
		"/":      `0`,
		"/a~1b":  `1`,
		"/c%d":   `2`,
		"/e^f":   `3`,
		"/g|h":   `4`,
		"/i\\j":  `5`,
		"/k\"l":  `6`,
		"/\x20":  `7`, // a single space
		"/m~0n":  `8`,
	} {
		got, err := MustParse(ptr).Lookup([]byte(rfcDoc))
		if err != nil || string(got) != want {
			t.Errorf("%q: %s %v, want %s", ptr, got, err, want)
		}
	}
	whole, err := MustParse("").Lookup([]byte(rfcDoc))
	if err != nil || !strings.HasPrefix(string(whole), "{") {
		t.Errorf("whole document: %s %v", whole, err)
	}
}

func TestNested(t *testing.T) {
	t.Parallel()
	doc := []byte(`{"type":"ticket.created","data":{"ticket":{"id":"T-42","amount":"12.50","tags":["a",{"x":true}]},"n":12345678901234567890}}`)
	for ptr, want := range map[string]string{
		"/data/ticket/id":       `"T-42"`,
		"/data/ticket/tags/1/x": `true`,
		"/data/n":               `12345678901234567890`, // exact, never through float64
	} {
		got, err := MustParse(ptr).Lookup(doc)
		if err != nil || string(got) != want {
			t.Errorf("%q: %s %v, want %s", ptr, got, err, want)
		}
	}
	for _, ptr := range []string{"/missing", "/data/ticket/tags/2", "/data/ticket/tags/-", "/data/ticket/tags/01", "/data/ticket/id/0", "/type/x", "/data/ticket/tags/x"} {
		if _, err := MustParse(ptr).Lookup(doc); !errors.Is(err, ErrNotFound) {
			t.Errorf("%q: %v, want not found", ptr, err)
		}
	}
}

func TestParseRefusesBadPointers(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"foo", "/a~", "/a~2", "/~x", strings.Repeat("/a", MaxTokens+1), "/" + strings.Repeat("a", MaxLen)} {
		if _, err := Parse(s); !errors.Is(err, ErrPointer) {
			t.Errorf("Parse(%q) = %v", s, err)
		}
	}
	p := MustParse("/a~1b/~0c/")
	if !slices.Equal(p.Tokens(), []string{"a/b", "~c", ""}) || p.String() != "/a~1b/~0c/" {
		t.Errorf("tokens %q", p.Tokens())
	}
}

// An ambiguous or broken document never yields a value (HR-276).
func TestLookupRefusesInvalidDocuments(t *testing.T) {
	t.Parallel()
	for _, doc := range []string{
		`{"id":"a","id":"b"}`,
		"{\"id\":\"\xff\"}",
		`{"id":"a"`,
		`{"id":"a"} trailing`,
		``,
		`{"id":"\ud800"}`,
	} {
		if _, err := MustParse("/id").Lookup([]byte(doc)); !errors.Is(err, ErrDocument) {
			t.Errorf("%q: %v, want invalid document", doc, err)
		}
	}
}

func TestLookupReturnsACopy(t *testing.T) {
	t.Parallel()
	doc := []byte(`{"a":"xyz"}`)
	v, err := MustParse("/a").Lookup(doc)
	if err != nil {
		t.Fatal(err)
	}
	doc[6] = 'Q'
	if string(v) != `"xyz"` {
		t.Fatalf("value aliases the document: %s", v)
	}
}

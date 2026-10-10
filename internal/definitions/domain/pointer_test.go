// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// TestHR190_PointersReadOnlyTheDeclaredScalar: a verifier reads one scalar
// at a reviewed pointer and nothing else.
func TestHR190_PointersReadOnlyTheDeclaredScalar(t *testing.T) {
	doc := []byte(`{"id":"re_1","amount":"30.00","n":12,"ok":true,"none":null,"obj":{"a~b":"x","c/d":"y"},
		"data":[{"id":"re_2"},{"id":"re_3"}]}`)
	for ptr, want := range map[string]string{
		"/id": "re_1", "/amount": "30.00", "/n": "12", "/ok": "true", "/obj/a~0b": "x", "/obj/c~1d": "y", "/data/1/id": "re_3",
	} {
		if got, ok := domain.PointerValue(doc, ptr); !ok || got != want {
			t.Errorf("%s: %q %v, want %q", ptr, got, ok, want)
		}
	}
	for _, ptr := range []string{"/missing", "/none", "/obj", "/data", "/data/2/id", "/data/01/id", "/data/-1/id", "id", ""} {
		if got, ok := domain.PointerValue(doc, ptr); ok {
			t.Errorf("%s: %q", ptr, got)
		}
	}
	for _, bad := range []string{`{"id":"a","id":"b"}`, `{"id":`, `[]`, `"re_1"`} {
		if got, ok := domain.PointerValue([]byte(bad), "/id"); ok {
			t.Errorf("%s: %q", bad, got)
		}
	}
}

func FuzzVerifierFields(f *testing.F) {
	f.Add([]byte(`{"id":"re_1","data":[{"id":"x"}]}`), "/data/0/id")
	f.Add([]byte(`{"a":{"b":1}}`), "/a/b")
	f.Fuzz(func(t *testing.T, doc []byte, ptr string) {
		if s, ok := domain.PointerValue(doc, ptr); ok && !domain.ValidPointer(ptr) {
			t.Fatalf("read %q at an invalid pointer %q", s, ptr)
		}
	})
}

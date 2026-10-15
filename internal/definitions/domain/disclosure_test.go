// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"math"
	"testing"
)

// TestDisclosureParamSpec: only free-byte params can be disclosure params;
// limits need the flag; max_bytes and max_entropy are bounded; defaults are
// 4096 bytes and 6 bits per byte (HR-079, G0 M10 D56).
func TestDisclosureParamSpec(t *testing.T) {
	for _, c := range []struct {
		name string
		p    ParamSpec
		ok   bool
	}{
		{"text", ParamSpec{Type: TypeText, Disclosure: true}, true},
		{"content with limits", ParamSpec{Type: TypeContent, Material: true, Disclosure: true, MaxBytes: 100, MaxEntropy: "5.25"}, true},
		{"identifier list", ParamSpec{Type: TypeIdentifierList, MaxItems: 3, Disclosure: true}, true},
		{"integer", ParamSpec{Type: TypeInteger, Unit: Units[0], Disclosure: true}, false},
		{"enum", ParamSpec{Type: TypeEnum, Values: []string{"a"}, Disclosure: true}, false},
		{"limits without the flag", ParamSpec{Type: TypeText, MaxBytes: 10}, false},
		{"entropy without the flag", ParamSpec{Type: TypeText, MaxEntropy: "4"}, false},
		{"too many bytes", ParamSpec{Type: TypeText, Disclosure: true, MaxBytes: maxParamText + 1}, false},
		{"entropy above 8", ParamSpec{Type: TypeText, Disclosure: true, MaxEntropy: "8.5"}, false},
		{"zero entropy", ParamSpec{Type: TypeText, Disclosure: true, MaxEntropy: "0"}, false},
		{"entropy not a decimal", ParamSpec{Type: TypeText, Disclosure: true, MaxEntropy: "1e1"}, false},
	} {
		if err := c.p.validate("p"); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if b, e := (ParamSpec{Type: TypeText, Disclosure: true}).DisclosureLimits(); b != 4096 || e != 6 {
		t.Fatalf("defaults %d %v", b, e)
	}
	if b, e := (ParamSpec{Type: TypeText, Disclosure: true, MaxBytes: 64, MaxEntropy: "4.5"}).DisclosureLimits(); b != 64 || e != 4.5 {
		t.Fatalf("declared %d %v", b, e)
	}
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	for _, c := range []struct {
		b    []byte
		want float64
	}{{nil, 0}, {[]byte("aaaa"), 0}, {[]byte("abab"), 1}, {all, 8}} {
		if got := Entropy(c.b); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("entropy %q = %v, want %v", c.b, got, c.want)
		}
	}
	if got := string((Value{Type: TypeIdentifierList, List: []string{"a", "b"}}).Disclosed()); got != "a\nb" {
		t.Fatalf("list disclosed %q", got)
	}
}

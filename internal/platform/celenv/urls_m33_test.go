// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package celenv

import (
	"context"
	"testing"
)

// TestHR748_CELURLFunctions: normurl, urlhost and urlquery give the one
// spelling, the host and the raw query of a URL, and "" for a value that is
// not an absolute http or https URL (an empty required value then fails the
// mapping).
func TestHR748_CELURLFunctions(t *testing.T) {
	e, err := New(DefaultLimits, nil)
	if err != nil {
		t.Fatal(err)
	}
	eval := func(src string) any {
		t.Helper()
		p, err := e.Compile(src, nil)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		v, _, err := p.Eval(context.Background(), map[string]any{})
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		return v.Value()
	}
	for src, want := range map[string]string{
		`normurl("HTTPS://Example.com:443/a?b=1#c")`: "https://example.com/a?b=1",
		`urlhost("https://Shop.Example.com:8443/p")`: "shop.example.com",
		`urlquery("https://example.com/?q=x%20y")`:   "q=x%20y",
		`urlhost("http://[::1]/")`:                   "[::1]",
	} {
		if got := eval(src); got != want {
			t.Errorf("%s = %v, want %q", src, got, want)
		}
	}
	for _, src := range []string{
		`normurl("ftp://example.com/")`,
		`normurl("https://user@example.com/")`,
		`urlhost("not a url")`,
		`urlhost("")`,
		`urlquery("javascript:void(0)")`,
	} {
		if got := eval(src); got != "" {
			t.Errorf("%s = %v, want \"\"", src, got)
		}
	}
}

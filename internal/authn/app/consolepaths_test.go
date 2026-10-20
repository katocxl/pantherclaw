// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"encoding/json/v2"
	"net/url"
	"os"
	"strings"
	"testing"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
)

// consoleVectors are the shared console return-path vectors.
func consoleVectors(t testing.TB) (accept, refuse []string) {
	t.Helper()
	b, err := os.ReadFile("testdata/console_paths.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Comment string   `json:"_comment"`
		Accept  []string `json:"accept"`
		Refuse  []string `json:"refuse"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Accept) < 5 || len(v.Refuse) < 20 {
		t.Fatalf("too few vectors: %d accept, %d refuse", len(v.Accept), len(v.Refuse))
	}
	return v.Accept, v.Refuse
}

// TestHR345_ConsoleReturnPaths: a sign-in may return to /app/ or any
// /app/<path> with a plain query; never anything with a scheme, host, "//",
// backslash, fragment, dot segment (also encoded), encoded slash,
// backslash or control character, or a byte outside the allowed set
// (testdata/console_paths.json, shared with the console). Every accepted
// path resolves on PantherClaw's own origin to itself.
func TestHR345_ConsoleReturnPaths(t *testing.T) {
	accept, refuse := consoleVectors(t)
	base, _ := url.Parse("https://pc.example.test")
	for _, p := range accept {
		if !authnapp.ValidConsolePath(p) || !authnapp.ValidReturnPath(p) {
			t.Errorf("refused %q", p)
			continue
		}
		u, err := url.Parse(p)
		if err != nil || u.Scheme != "" || u.Host != "" || u.Fragment != "" {
			t.Errorf("%q parses as %#v (%v)", p, u, err)
			continue
		}
		if r := base.ResolveReference(u); r.Host != base.Host || r.Scheme != base.Scheme || !strings.HasPrefix(r.EscapedPath(), "/app/") {
			t.Errorf("%q opens as %s", p, r)
		}
	}
	for _, p := range refuse {
		if authnapp.ValidConsolePath(p) || authnapp.ValidReturnPath(p) {
			t.Errorf("accepted %q", p)
		}
	}
	if long := "/app/" + strings.Repeat("a", 508); authnapp.ValidConsolePath(long) || !authnapp.ValidConsolePath(long[:512]) {
		t.Error("the 512-byte bound")
	}
}

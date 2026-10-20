// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"net/url"
	"path"
	"strings"
	"testing"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
)

// FuzzNextPath (G0 M5 part 1, HR-152): no `next` value, as given or as
// GET /login's query decodes it, panics the check, and a path it accepts
// is a clean same-origin path: it resolves on PantherClaw's own host to
// itself, with no scheme, host, query, fragment, escape, backslash, dot
// segment or control character a browser could read another way.
//
// Console paths (HR-345, G0 UI D78) may carry a trailing slash, a plain
// query and percent-escapes; an accepted one still resolves on PantherClaw's
// own host under /app/, with no scheme, host, fragment, backslash, "//",
// control character, or escape a browser would read as a slash, backslash,
// control character or dot segment.
func FuzzNextPath(f *testing.F) {
	for _, s := range []string{
		"/account", "/containment", "/approvals", "/approvals/0192f3a0-0000-7000-8000-000000000001",
		"/approvals/0192F3A0-0000-7000-8000-000000000001", "/approvals/../account", "/approvals/", "//approvals",
		"//evil.example", `/\evil.example`, "/%2F%2Fevil.example", "https://evil.example/account", "/account?x=1",
		"/account#x", "/account/", "/./account", " /account", "/account\t", "%2Faccount", "/account%00", "",
		// Console pages (HR-345).
		"/app", "/app/", "/app/agents/1", "/app//evil.example", "/app/../account", "/app/./x", "/app?x=1", "/app/%2F",
		`/app\evil.example`, "/apps", "/app/x/",
	} {
		f.Add(s)
	}
	base, err := url.Parse("https://pc.example.test")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		check := func(next string) {
			if !authnapp.ValidReturnPath(next) {
				return
			}
			if strings.HasPrefix(next, "/app/") {
				checkConsolePath(t, base, next)
				return
			}
			if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, `\%?#@:`) ||
				strings.ContainsFunc(next, func(r rune) bool { return r <= ' ' || r >= 0x7f }) || path.Clean(next) != next {
				t.Fatalf("accepted the return path %q", next)
			}
			u, err := url.Parse(next)
			if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
				u.Path != next || u.RawPath != "" {
				t.Fatalf("accepted %q, which parses as %#v (%v)", next, u, err)
			}
			if r := base.ResolveReference(u); r.Host != base.Host || r.Scheme != base.Scheme || r.Path != next {
				t.Fatalf("accepted %q, which a browser opens as %s", next, r)
			}
		}
		check(s)
		if q, err := url.ParseQuery("org=o&next=" + s); err == nil {
			check(q.Get("next"))
		}
	})
}

// checkConsolePath is FuzzNextPath's invariant for an accepted console
// path (HR-345).
func checkConsolePath(t *testing.T, base *url.URL, next string) {
	t.Helper()
	if strings.HasPrefix(next, "//") || strings.Contains(next, "//") || strings.ContainsAny(next, `\#@ `) || len(next) > 512 ||
		strings.ContainsFunc(next, func(r rune) bool { return r < ' ' || r >= 0x7f }) {
		t.Fatalf("accepted the console path %q", next)
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		t.Fatalf("accepted %q, which parses as %#v (%v)", next, u, err)
	}
	if strings.ContainsAny(u.Path, `\`) || strings.Contains(u.Path, "//") || strings.Contains(u.RawQuery, "/") {
		t.Fatalf("accepted %q, whose escapes decode to a slash or backslash", next)
	}
	if strings.ContainsFunc(u.Path+u.RawQuery, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		t.Fatalf("accepted %q, whose escapes decode to a control character", next)
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			t.Fatalf("accepted %q, with a dot segment once decoded", next)
		}
	}
	if r := base.ResolveReference(u); r.Host != base.Host || r.Scheme != base.Scheme || !strings.HasPrefix(r.Path, "/app/") || r.Path != u.Path {
		t.Fatalf("accepted %q, which a browser opens as %s", next, r)
	}
}

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
func FuzzNextPath(f *testing.F) {
	for _, s := range []string{
		"/account", "/containment", "/approvals", "/approvals/0192f3a0-0000-7000-8000-000000000001",
		"/approvals/0192F3A0-0000-7000-8000-000000000001", "/approvals/../account", "/approvals/", "//approvals",
		"//evil.example", `/\evil.example`, "/%2F%2Fevil.example", "https://evil.example/account", "/account?x=1",
		"/account#x", "/account/", "/./account", " /account", "/account\t", "%2Faccount", "/account%00", "",
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

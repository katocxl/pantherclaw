// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webguard_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webguard"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
)

const origin = "https://pc.example.test"

// TestHR342_SameOrigin: only same-origin Fetch Metadata (with a matching
// Origin when one is sent), or no Fetch Metadata and exactly the public
// Origin, prove the page.
func TestHR342_SameOrigin(t *testing.T) {
	for _, tc := range []struct {
		site, origin string
		ok           bool
	}{
		{"same-origin", origin, true},
		{"same-origin", "", true},
		{"same-origin", "https://evil.example", false},
		{"same-origin", "null", false},
		{"same-origin", origin + "/", false},
		{"same-origin", "http://pc.example.test", false},
		{"same-site", origin, false},
		{"same-site", "", false},
		{"cross-site", origin, false},
		{"cross-site", "", false},
		{"none", origin, false},
		{"none", "", false},
		{"Same-Origin", origin, false},
		{"", origin, true},
		{"", "", false},
		{"", "https://evil.example", false},
		{"", "null", false},
		{"", "https://pc.example.test:443", false},
	} {
		h := http.Header{}
		if tc.site != "" {
			h.Set("Sec-Fetch-Site", tc.site)
		}
		if tc.origin != "" {
			h.Set("Origin", tc.origin)
		}
		if got := webguard.SameOrigin(h.Get, origin); got != tc.ok {
			t.Errorf("Sec-Fetch-Site %q, Origin %q: %v, want %v", tc.site, tc.origin, got, tc.ok)
		}
	}
}

type nopAuth struct{}

func (nopAuth) Authenticate(context.Context, string) (authnapp.BrowserSession, error) {
	return authnapp.BrowserSession{}, authnapp.ErrUnauthenticated
}

func (nopAuth) Recheck(context.Context, string) (authnapp.BrowserSession, error) {
	return authnapp.BrowserSession{}, authnapp.ErrUnauthenticated
}

// TestHR150_SessionCookie: the cookie is __Host-pc_session on https and
// pc_session only on an http (loopback) URL; it is found among several
// Cookie lines, the first non-empty value of the exact name wins, and
// look-alike names never count. A rotated secret is set with the HR-150
// attributes.
func TestHR150_SessionCookie(t *testing.T) {
	https, err := webguard.NewSessions(nopAuth{}, origin)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := webguard.NewSessions(nopAuth{}, "http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if https.CookieName() != "__Host-pc_session" || plain.CookieName() != "pc_session" || https.PublicOrigin() != origin {
		t.Fatalf("names %q %q, origin %q", https.CookieName(), plain.CookieName(), https.PublicOrigin())
	}
	for _, tc := range []struct {
		lines []string
		want  string
	}{
		{[]string{"__Host-pc_session=s1"}, "s1"},
		{[]string{"a=1; __Host-pc_session=s1; b=2"}, "s1"},
		{[]string{"a=1", "__Host-pc_session=s2"}, "s2"},
		{[]string{"__Host-pc_session=; __Host-pc_session=s3"}, "s3"},
		{[]string{"__Host-pc_session=s4; __Host-pc_session=s5"}, "s4"},
		{[]string{"pc_session=plain"}, ""},
		{[]string{"__host-pc_session=x"}, ""},
		{[]string{"__Host-pc_session_x=x", "x__Host-pc_session=y"}, ""},
		{[]string{""}, ""},
		{nil, ""},
	} {
		got, ok := https.Cookie(tc.lines)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("Cookie(%q) = %q, %v; want %q", tc.lines, got, ok, tc.want)
		}
	}
	if got, ok := plain.Cookie([]string{"__Host-pc_session=x; pc_session=p"}); !ok || got != "p" {
		t.Errorf("plain: %q %v", got, ok)
	}
	sc := https.SetCookie("rotated")
	for _, want := range []string{"__Host-pc_session=rotated", "Path=/", "HttpOnly", "Secure", "SameSite=Strict", "Max-Age=43200"} {
		if !strings.Contains(sc, want) {
			t.Errorf("Set-Cookie %q lacks %q", sc, want)
		}
	}
	if strings.Contains(sc, "Domain") || strings.Contains(plain.SetCookie("x"), "Secure") {
		t.Errorf("Set-Cookie %q / %q", sc, plain.SetCookie("x"))
	}
	for _, bad := range []string{"", "pc.example.test", "ftp://pc.example.test", "/relative"} {
		if _, err := webguard.NewSessions(nopAuth{}, bad); err == nil {
			t.Errorf("public URL %q accepted", bad)
		}
	}
	if _, err := webguard.NewSessions(nil, origin); err == nil {
		t.Error("nil authenticator accepted")
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package actionir_test

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// TestHR748_URLsHaveOneSpelling: an absolute http or https URL has one
// spelling: lowercase scheme and host, no default port, no fragment, an
// empty path as "/", and the escaped path and raw query as sent. The
// spelling is a fixed point, and URLHost and URLQuery read it.
func TestHR748_URLsHaveOneSpelling(t *testing.T) {
	for in, want := range map[string]string{
		"https://Example.COM/A/b?Q=1#frag":        "https://example.com/A/b?Q=1",
		"HTTPS://example.com:443":                 "https://example.com/",
		"http://example.com:80/x":                 "http://example.com/x",
		"http://example.com:8080/x":               "http://example.com:8080/x",
		"https://example.com:80/x":                "https://example.com:80/x",
		"https://example.com?":                    "https://example.com/?",
		"https://example.com/%7Euser/a%2Fb?x=%41": "https://example.com/%7Euser/a%2Fb?x=%41",
		"http://[2001:DB8::1]:80/":                "http://[2001:db8::1]/",
		"https://10.0.0.1/admin":                  "https://10.0.0.1/admin",
	} {
		got := actionir.NormalizeURL(in)
		if got != want {
			t.Errorf("NormalizeURL(%q) = %q, want %q", in, got, want)
			continue
		}
		if again := actionir.NormalizeURL(got); again != got {
			t.Errorf("NormalizeURL is not a fixed point on %q: %q", got, again)
		}
	}
	for in, want := range map[string]string{
		"https://Shop.Example.com:8443/p": "shop.example.com",
		"http://[::1]:8080/":              "[::1]",
		"https://192.0.2.7/":              "192.0.2.7",
	} {
		if got := actionir.URLHost(in); got != want {
			t.Errorf("URLHost(%q) = %q, want %q", in, got, want)
		}
	}
	if got := actionir.URLQuery("https://example.com/s?q=a%20b&x=1#f"); got != "q=a%20b&x=1" {
		t.Errorf("URLQuery = %q", got)
	}
}

// TestHR748_InvalidURLsHaveNoSpelling: a value that is not printable ASCII,
// is longer than MaxURL, is not absolute http or https, has no host or has
// userinfo has no spelling: all three functions return "".
func TestHR748_InvalidURLsHaveNoSpelling(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("a", actionir.MaxURL)
	for _, in := range []string{
		"",
		"example.com/path",
		"/relative/path",
		"ftp://example.com/",
		"javascript:alert(1)",
		"file:///etc/passwd",
		"https://user:pass@example.com/",
		"https://user@example.com/",
		"https:///nohost",
		"https://exämple.com/",
		"https://example.com/\x00",
		"https://example.com/a b\n",
		"mailto:a@example.com",
		long,
	} {
		if got := actionir.NormalizeURL(in); got != "" {
			t.Errorf("NormalizeURL(%q) = %q, want \"\"", in, got)
		}
		if got := actionir.URLHost(in); got != "" {
			t.Errorf("URLHost(%q) = %q, want \"\"", in, got)
		}
		if got := actionir.URLQuery(in); got != "" {
			t.Errorf("URLQuery(%q) = %q, want \"\"", in, got)
		}
	}
}

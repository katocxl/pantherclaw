// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/mcpcatalog/domain"
)

var digest = "sha256:" + strings.Repeat("ab", 32)

// TestHR585_MatchingIsExact: a catalog server matches only what it names.
// Near-matches of a URL, an image or a package are other servers, and a URL
// that hides where it goes matches nothing (T-253).
//
// Covers: F873
func TestHR585_MatchingIsExact(t *testing.T) {
	host := domain.Spec{Host: "mcp.example.com", PathPrefix: "/github"}
	cases := []struct {
		name string
		spec domain.Spec
		c    domain.Candidate
		want bool
	}{
		{"the prefix itself", host, domain.URLCandidate("https://mcp.example.com/github"), true},
		{"below the prefix", host, domain.URLCandidate("https://mcp.example.com/github/sse"), true},
		{"case and default port fold", host, domain.URLCandidate("https://MCP.Example.com:443/github"), true},
		{"a longer last segment", host, domain.URLCandidate("https://mcp.example.com/github-evil"), false},
		{"another prefix", host, domain.URLCandidate("https://mcp.example.com/gitlab"), false},
		{"a dot segment out of the prefix", host, domain.URLCandidate("https://mcp.example.com/github/../admin"), false},
		{"an escaped dot segment", host, domain.URLCandidate("https://mcp.example.com/github/%2e%2e/admin"), false},
		{"a suffix of the host", host, domain.URLCandidate("https://evil-mcp.example.com/github"), false},
		{"the host as a label of another", host, domain.URLCandidate("https://mcp.example.com.evil.test/github"), false},
		{"a similar host", host, domain.URLCandidate("https://mcp.examp1e.com/github"), false},
		{"a homoglyph of the host", host, domain.URLCandidate("https://mcp.exаmple.com/github"), false},
		{"another port", host, domain.URLCandidate("https://mcp.example.com:8443/github"), false},
		{"http on its default port is not a bare host", host, domain.URLCandidate("http://mcp.example.com/github"), false},
		{"http on 80 is not a bare host", host, domain.URLCandidate("http://mcp.example.com:80/github"), false},
		{"http on 443 is not https", host, domain.URLCandidate("http://mcp.example.com:443/github"), false},
		{"a port in the spec is that port", domain.Spec{Host: "mcp.example.com:8443"}, domain.URLCandidate("https://mcp.example.com:8443/x"), true},
		{"over https only", domain.Spec{Host: "mcp.example.com:8443"}, domain.URLCandidate("http://mcp.example.com:8443/x"), false},
		{"not the default port", domain.Spec{Host: "mcp.example.com:8443"}, domain.URLCandidate("https://mcp.example.com/x"), false},
		{"credentials in the URL", host, domain.URLCandidate("https://mcp.example.com@evil.test/github"), false},
		{"a user on the right host", host, domain.URLCandidate("https://a@mcp.example.com/github"), false},
		{"no prefix covers the host", domain.Spec{Host: "mcp.example.com"}, domain.URLCandidate("https://mcp.example.com/any/path"), true},
		{"the same digest", domain.Spec{ImageDigest: digest}, domain.ImageCandidate("ghcr.io/acme/mcp@" + digest), true},
		{"a bare digest", domain.Spec{ImageDigest: digest}, domain.ImageCandidate(digest), true},
		{"another digest", domain.Spec{ImageDigest: digest}, domain.ImageCandidate(strings.ReplaceAll(digest, "ab", "ac")), false},
		{"a tag is no digest", domain.Spec{ImageDigest: digest}, domain.ImageCandidate("ghcr.io/acme/mcp:latest"), false},
		{"the same package", domain.Spec{PackageRef: "@acme/mcp"}, domain.Candidate{PackageRef: "@acme/mcp"}, true},
		{"a similar package", domain.Spec{PackageRef: "@acme/mcp"}, domain.Candidate{PackageRef: "@acme/mcp-server"}, false},
		{"package case stays", domain.Spec{PackageRef: "@acme/mcp"}, domain.Candidate{PackageRef: "@Acme/mcp"}, false},
		{"a package does not cover a URL", domain.Spec{PackageRef: "github"}, domain.URLCandidate("https://evil.test/github"), false},
		{"the explicit http form", domain.Spec{Host: "http://10.0.0.5:8080"}, domain.URLCandidate("http://10.0.0.5:8080/mcp"), true},
		{"the explicit http form on 80", domain.Spec{Host: "http://10.0.0.5:80"}, domain.URLCandidate("http://10.0.0.5/mcp"), true},
		{"the explicit http form is not https", domain.Spec{Host: "http://10.0.0.5:8080"}, domain.URLCandidate("https://10.0.0.5:8080/mcp"), false},
		{"the explicit http form is its port", domain.Spec{Host: "http://10.0.0.5:8080"}, domain.URLCandidate("http://10.0.0.5:8081/mcp"), false},
		{"the explicit http form over IPv6", domain.Spec{Host: "http://[fd00::1]:8080"}, domain.URLCandidate("http://[fd00::1]:8080/mcp"), true},
		{"an empty candidate", host, domain.Candidate{}, false},
		{"an empty spec", domain.Spec{}, domain.Candidate{}, false},
	}
	for _, c := range cases {
		if got := c.spec.Matches(c.c); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestF875_ADenialCoversEveryWayToTheSameEndpoint: an approval stays exact, a
// denial does not: changing the scheme or spelling the port never escapes a
// revoke, while another host or port is still another server (D266).
//
// Covers: F875
func TestF875_ADenialCoversEveryWayToTheSameEndpoint(t *testing.T) {
	bare := domain.Spec{Host: "mcp.example.com"}
	ported := domain.Spec{Host: "mcp.example.com:8443"}
	cases := []struct {
		name string
		spec domain.Spec
		raw  string
		want bool
	}{
		{"https on 443", bare, "https://mcp.example.com/x", true},
		{"http on 80", bare, "http://mcp.example.com/x", true},
		{"http with 80 spelled", bare, "http://mcp.example.com:80/x", true},
		{"http on 443", bare, "http://mcp.example.com:443/x", true},
		{"https on 80", bare, "https://mcp.example.com:80/x", true},
		{"a bare host on another port", bare, "https://mcp.example.com:8443/x", false},
		{"http on the named port", ported, "http://mcp.example.com:8443/x", true},
		{"https on the named port", ported, "https://mcp.example.com:8443/x", true},
		{"a named port is that port", ported, "http://mcp.example.com/x", false},
		{"another host", bare, "http://mcp.example.org/x", false},
		{"a host is no prefix of a host", bare, "http://mcp.example.com.evil.test/x", false},
		{"the path still counts", domain.Spec{Host: "mcp.example.com", PathPrefix: "/a"}, "http://mcp.example.com/b", false},
		{"under the path", domain.Spec{Host: "mcp.example.com", PathPrefix: "/a"}, "http://mcp.example.com/a/b", true},
		{"the http form covers https", domain.Spec{Host: "http://10.0.0.5:8080"}, "https://10.0.0.5:8080/x", true},
		{"an IPv6 host", domain.Spec{Host: "[fd00::1]:8080"}, "http://[fd00::1]:8080/x", true},
		{"credentials still match nothing", bare, "http://a@mcp.example.com/x", false},
	}
	for _, c := range cases {
		if got := c.spec.Denies(domain.URLCandidate(c.raw)); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if !(domain.Spec{Host: "mcp.example.com"}).Denies(domain.Candidate{Host: "mcp.example.com"}) {
		t.Error("a scan's bare host")
	}
	if !(domain.Spec{ImageDigest: digest}).Denies(domain.ImageCandidate(digest)) {
		t.Error("a denial covers what an approval matches")
	}
}

// TestHR585_ASpecHasNoWildcard: what a person proposes cannot be fuzzy.
//
// Covers: F873
func TestHR585_ASpecHasNoWildcard(t *testing.T) {
	bad := []domain.Spec{
		{},
		{Host: "*.example.com"},
		{Host: "example.*"},
		{Host: "exa mple.com"},
		{Host: "https://example.com"},
		{Host: "http://example.com:8080"},
		{Host: "http://8.8.8.8:8080"},
		{Host: "http://10.0.0.5"},
		{Host: "http://10.0.0.5:0"},
		{Host: "http://[::ffff:10.0.0.5]:8080"},
		{Host: "http://169.254.169.254:80"},
		{Host: "example.com/path"},
		{PathPrefix: "/mcp"},
		{Host: "example.com", PathPrefix: "mcp"},
		{Host: "example.com", PathPrefix: "/mcp/*"},
		{Host: "example.com", PathPrefix: "/a/../b"},
		{Host: "example.com", PathPrefix: "/a%2fb"},
		{ImageDigest: "sha256:abc"},
		{ImageDigest: "ghcr.io/acme/mcp:latest"},
		{PackageRef: "@acme/*"},
		{PackageRef: "acme mcp"},
	}
	for _, s := range bad {
		if _, err := s.Normalize(); err == nil {
			t.Errorf("%+v was accepted", s)
		}
	}
	got, err := domain.Spec{Host: "MCP.Example.com:443", PathPrefix: "/mcp/"}.Normalize()
	if err != nil || got.Host != "mcp.example.com" || got.PathPrefix != "/mcp" {
		t.Fatalf("normalized: %+v %v", got, err)
	}
}

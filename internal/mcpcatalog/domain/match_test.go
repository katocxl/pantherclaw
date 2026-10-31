// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/mcpcatalog/domain"
)

var digest = "sha256:" + strings.Repeat("ab", 32)

// TestHR585_MatchingIsExact: a catalogue server matches only what it names.
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
		{"an empty candidate", host, domain.Candidate{}, false},
		{"an empty spec", domain.Spec{}, domain.Candidate{}, false},
	}
	for _, c := range cases {
		if got := c.spec.Matches(c.c); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
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

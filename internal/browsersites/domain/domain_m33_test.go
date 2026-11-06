// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"strings"
	"testing"
)

// TestHR749_ASiteHostIsALowerCaseDNSName: a site host is a lower-case DNS
// name of at least two labels, at most 253 bytes, with no IP, no port, no
// wildcard and no trailing dot.
func TestHR749_ASiteHostIsALowerCaseDNSName(t *testing.T) {
	label := strings.Repeat("a", 63)
	long := strings.Repeat(label+".", 3) + strings.Repeat("b", 61) // 253
	for _, h := range []string{"example.com", "docs.example.co.uk", "x-1.example.com", "a.b", "xn--bcher-kva.example", long} {
		if !ValidHost(h) {
			t.Errorf("%q refused", h)
		}
	}
	for _, h := range []string{
		"", "localhost", "Example.com", "example.com.", ".example.com", "*.example.com", "example.com:443",
		"10.0.0.1", "1.2.3", "[::1]", "-a.example.com", "a-.example.com", "exa mple.com", "exämple.com",
		strings.Repeat("a", 64) + ".com", long + "c", "https://example.com",
	} {
		if ValidHost(h) {
			t.Errorf("%q accepted", h)
		}
	}
}

// TestHR749_SelectorsAndNotesAreBounded: at most 16 selectors of 1..256
// characters, a note of at most 256 characters.
func TestHR749_SelectorsAndNotesAreBounded(t *testing.T) {
	sixteen := make([]string, MaxSelectors)
	for i := range sixteen {
		sixteen[i] = "button.x"
	}
	if !ValidSelectors(nil) || !ValidSelectors(sixteen) || !ValidSelectors([]string{strings.Repeat("é", 256)}) {
		t.Fatal("valid selectors refused")
	}
	if ValidSelectors(append(sixteen, "a")) || ValidSelectors([]string{""}) || ValidSelectors([]string{strings.Repeat("a", 257)}) ||
		ValidSelectors([]string{"\xff"}) {
		t.Fatal("invalid selectors accepted")
	}
	if !ValidNote("") || !ValidNote(strings.Repeat("é", 256)) || ValidNote(strings.Repeat("a", 257)) || ValidNote("\xff") {
		t.Fatal("note bounds")
	}
}

// TestHR745_SitesMatchTheirHostAndSubdomainsOnly: a host matches an entry
// equal to it, or a subdomain of an entry with include_subdomains; an IP
// never matches and an empty list matches nothing.
func TestHR745_SitesMatchTheirHostAndSubdomainsOnly(t *testing.T) {
	sites := []Site{{Host: "example.com"}, {Host: "example.org", IncludeSubdomains: true}, {Host: "10.0.0.1"}}
	for host, want := range map[string]bool{
		"example.com": true, "a.example.com": false, "example.org": true, "a.b.example.org": true,
		"badexample.org": false, "example.org.evil.test": false, "10.0.0.1": false, "[::1]": false, "": false,
	} {
		if got := Matches(host, sites); got != want {
			t.Errorf("Matches(%q) = %v", host, got)
		}
	}
	if Matches("example.com", nil) {
		t.Error("an empty list matched")
	}
}

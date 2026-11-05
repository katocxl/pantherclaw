// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the formats and matching of the org's browser sites
// (G0 M33 D976, D977; HR-745, HR-749). It is pure.
package domain

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Limits (pc.browser_sites).
const (
	// SiteLimit is the most sites one org lists (BROWSER_SITE_LIMIT).
	SiteLimit = 500
	// MaxSelectors bounds a site's marked-click selectors, each 1..
	// MaxSelectorLen characters.
	MaxSelectors   = 16
	MaxSelectorLen = 256
	// MaxNote bounds a site's note, in characters.
	MaxNote = 256
)

var (
	// A lower-case hostname: dot-separated labels of letters, digits and
	// inner hyphens, at least two labels (the owned accounts' domainRe).
	hostRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	ipv4Re = regexp.MustCompile(`^[0-9.]+$`)
)

// ValidHost reports whether h is a site host: a lower-case DNS name of at
// least two labels, at most 253 bytes, no IP and no port.
func ValidHost(h string) bool {
	return h != "" && len(h) <= 253 && hostRe.MatchString(h) && !ipv4Re.MatchString(h)
}

// ValidSelectors reports whether s are at most MaxSelectors selectors of
// 1..MaxSelectorLen characters of UTF-8.
func ValidSelectors(s []string) bool {
	if len(s) > MaxSelectors {
		return false
	}
	for _, x := range s {
		if n := utf8.RuneCountInString(x); !utf8.ValidString(x) || n < 1 || n > MaxSelectorLen {
			return false
		}
	}
	return true
}

// ValidNote reports whether n is at most MaxNote characters of UTF-8.
func ValidNote(n string) bool {
	return utf8.ValidString(n) && utf8.RuneCountInString(n) <= MaxNote
}

// Site is one listed site as matching sees it.
type Site struct {
	Host              string
	IncludeSubdomains bool
}

// Matches reports whether host matches one of sites (D977): host equals a
// site's host, or the site includes subdomains and host ends with "." and
// its host. An IP host never matches.
func Matches(host string, sites []Site) bool {
	if host == "" || strings.HasPrefix(host, "[") || ipv4Re.MatchString(host) {
		return false
	}
	for _, s := range sites {
		if host == s.Host || (s.IncludeSubdomains && strings.HasSuffix(host, "."+s.Host)) {
			return true
		}
	}
	return false
}

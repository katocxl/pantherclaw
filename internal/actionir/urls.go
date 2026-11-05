// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package actionir

import (
	"net/url"
	"strings"
)

// MaxURL bounds a url value (G0 M33 D975).
const MaxURL = 2048

// NormalizeURL returns the one spelling of an absolute http or https URL
// (G0 M33 D975, HR-748), or "" when s is not one: printable ASCII only, at
// most MaxURL bytes, parsed by net/url as absolute http or https with a
// host and without userinfo. The scheme and host are lower-cased, the
// default port is dropped, the fragment is dropped, an empty path becomes
// "/", and the escaped path and the raw query are kept exactly as sent.
// Hosts must already be ASCII (a browser sends punycode).
//
// The result is a fixed point: NormalizeURL returns it unchanged.
func NormalizeURL(s string) string {
	p, ok := parseURL(s)
	if !ok {
		return ""
	}
	out := p.scheme + "://" + p.host + p.port + p.path
	if p.query != "" || p.forceQuery {
		out += "?" + p.query
	}
	return out
}

// URLHost returns the host of an absolute http or https URL without its
// port, lower-cased, an IPv6 address in brackets, or "" when s is not one
// (G0 M33 D975).
func URLHost(s string) string {
	p, ok := parseURL(s)
	if !ok {
		return ""
	}
	return p.host
}

// URLQuery returns the raw query of an absolute http or https URL as sent,
// or "" when s is not one or has no query (G0 M33 D975).
func URLQuery(s string) string {
	p, ok := parseURL(s)
	if !ok {
		return ""
	}
	return p.query
}

type urlParts struct {
	scheme, host, port, path, query string
	forceQuery                      bool
}

func parseURL(s string) (urlParts, bool) {
	if s == "" || len(s) > MaxURL {
		return urlParts{}, false
	}
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return urlParts{}, false
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" {
		return urlParts{}, false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return urlParts{}, false
	}
	// The authority and path as sent: after "scheme://", up to the first
	// "/", "?" or "#"; the path then runs to the first "?" or "#".
	rest, ok := cutPrefixFold(s, u.Scheme+"://")
	if !ok {
		return urlParts{}, false
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority := rest[:end]
	if strings.Contains(authority, "@") {
		return urlParts{}, false
	}
	rest = rest[end:]
	pathEnd := strings.IndexAny(rest, "?#")
	if pathEnd < 0 {
		pathEnd = len(rest)
	}
	path := rest[:pathEnd]
	if path == "" {
		path = "/"
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return urlParts{}, false
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		port = ":" + port
	}
	return urlParts{scheme: scheme, host: host, port: port, path: path, query: u.RawQuery, forceQuery: u.ForceQuery}, true
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return s, false
	}
	return s[len(prefix):], true
}

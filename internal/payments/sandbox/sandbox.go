// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package sandbox is the agent payments sandbox host allow-list (G0 M39
// D1120, D1124c; HR-831), with no database or network dependency, so the
// server's trust anchors and connections and the gateway's merchant
// endpoint check use one list.
package sandbox

import (
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// hosts is the sandbox host allow-list: the only hosts an anchor URL or an
// agent payment merchant endpoint may name besides loopback. It is empty:
// adding a sandbox host is a code change, and there is no live switch.
var hosts = []string{}

// Loopback are the ranges the simulator reaches (D1120).
var Loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

// IsLoopbackHost reports whether h is localhost or a loopback literal.
func IsLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(strings.Trim(h, "[]"))
	return err == nil && a.IsLoopback()
}

// Host reports whether host is on the sandbox allow-list or loopback.
func Host(host string) bool {
	h := strings.ToLower(host)
	return IsLoopbackHost(h) || slices.Contains(hosts, h)
}

// URL reports whether raw is an https URL without credentials, fragment
// or opaque part (ok), and whether its host is a sandbox host (sandbox).
// A URL that is not ok is never sandbox.
func URL(raw string) (ok, isSandbox bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false, false
	}
	return true, Host(u.Hostname())
}

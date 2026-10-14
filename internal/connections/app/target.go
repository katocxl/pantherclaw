// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// endpoint is a host and an effective port.
type endpoint struct {
	host string // lower-case name, or an address in canonical form
	port int
}

func (e endpoint) String() string {
	h := e.host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return h + ":" + strconv.Itoa(e.port)
}

var (
	labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	segRe   = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
)

// canonicalHost lower-cases a host name and drops a trailing dot; an IP
// address in any spelling (httpx.HostAddr) becomes its canonical form.
func canonicalHost(h string) (host string, addr netip.Addr, isAddr, ok bool) {
	if a, isIP := httpx.HostAddr(h); isIP {
		return a.String(), a, true, true
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" || len(h) > 253 {
		return "", netip.Addr{}, false, false
	}
	for _, l := range strings.Split(h, ".") {
		if !labelRe.MatchString(l) {
			return "", netip.Addr{}, false, false
		}
	}
	return h, netip.Addr{}, false, true
}

// ownEndpoints are PantherClaw's own public URL and gateway listener, which
// a connection never targets (HR-077).
func ownEndpoints(urls ...string) []endpoint {
	var out []endpoint
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		h, _, _, ok := canonicalHost(u.Hostname())
		if !ok {
			continue
		}
		out = append(out, endpoint{host: h, port: effectivePort(u)})
	}
	return out
}

func effectivePort(u *url.URL) int {
	if p, err := strconv.Atoi(u.Port()); err == nil {
		return p
	}
	if u.Scheme == "http" {
		return 80
	}
	return 443
}

// refused reports a host that a connection may never name: a metadata
// service in any spelling (HR-077).
func refused(host string, addr netip.Addr, isAddr bool) bool {
	return (isAddr && httpx.MetadataAddr(addr)) || (!isAddr && httpx.MetadataHost(host))
}

// checkBaseURL validates and normalizes a connection's base URL: https, or
// http only for a private address literal (the gateway's operator lists the
// ranges its gateway may reach, and its dial-time checks still apply); no
// credentials, query or fragment; a path prefix of plain segments; not a
// metadata service and not PantherClaw itself.
func checkBaseURL(raw string, own []endpoint) (string, endpoint, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" ||
		strings.ContainsAny(raw, "\\ \t\r\n") || (u.Scheme != "https" && u.Scheme != "http") {
		return "", endpoint{}, ErrBaseURL
	}
	host, addr, isAddr, ok := canonicalHost(u.Hostname())
	if !ok || refused(host, addr, isAddr) {
		return "", endpoint{}, ErrBaseURL
	}
	if u.Scheme == "http" && (!isAddr || (!addr.IsPrivate() && !addr.IsLoopback())) {
		return "", endpoint{}, ErrPlainHTTP
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", endpoint{}, ErrBaseURL
		}
	}
	ep := endpoint{host: host, port: effectivePort(u)}
	if slices.Contains(own, ep) {
		return "", endpoint{}, ErrOwnHost
	}
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	for _, seg := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if path != "" && (!segRe.MatchString(seg) || seg == "." || seg == "..") {
			return "", endpoint{}, ErrBaseURL
		}
	}
	hostPort := host
	if isAddr && addr.Is6() {
		hostPort = "[" + host + "]"
	}
	if u.Port() != "" {
		hostPort += ":" + u.Port()
	}
	return u.Scheme + "://" + hostPort + path, ep, nil
}

// localLiteral reports whether a normalized base URL names an IP literal on
// loopback (127.0.0.0/8, ::1) or a private network (10/8, 172.16/12,
// 192.168/16, fc00::/7): the only targets of a simulated connection (HR-221).
// A name is never local, and an IPv4-mapped IPv6 address is not accepted.
func localLiteral(base string) bool {
	u, err := url.Parse(base)
	return err == nil && localHost(u.Hostname())
}

// localHost reports whether a bare host (no port, no brackets) is such a literal.
func localHost(h string) bool {
	addr, err := netip.ParseAddr(h)
	if err != nil || addr.Is4In6() || addr.Zone() != "" {
		return false
	}
	return addr.IsLoopback() || addr.IsPrivate()
}

// checkSimulated applies HR-221 to a simulated http or mcp connection: its
// base URL and every host a credential may be sent to are local literals.
func checkSimulated(base *string, hosts []string) error {
	if base != nil && !localLiteral(*base) {
		return ErrSimulatedTarget
	}
	for _, entry := range hosts {
		name, _, err := net.SplitHostPort(entry)
		if err != nil {
			name = strings.TrimSuffix(strings.TrimPrefix(entry, "["), "]")
		}
		if !localHost(name) {
			return ErrSimulatedTarget
		}
	}
	return nil
}

// checkAllowedHosts validates the hosts a credential may be sent to:
// "host" (any port) or "host:port". The default is the base URL's host,
// with its port when it is not the scheme's default.
func checkAllowedHosts(hosts []string, base endpoint, baseURL string, own []endpoint) ([]string, error) {
	if len(hosts) == 0 {
		u, _ := url.Parse(baseURL)
		h := base.host
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
		if u.Port() != "" {
			h += ":" + u.Port()
		}
		return []string{h}, nil
	}
	if len(hosts) > maxAllowedHosts {
		return nil, ErrAllowedHosts
	}
	out := make([]string, 0, len(hosts))
	for _, entry := range hosts {
		name, port, err := net.SplitHostPort(entry)
		if err != nil {
			name, port = strings.TrimSuffix(strings.TrimPrefix(entry, "["), "]"), ""
		}
		host, addr, isAddr, ok := canonicalHost(name)
		if !ok || refused(host, addr, isAddr) {
			return nil, ErrAllowedHosts
		}
		n := 0
		if port != "" {
			if n, err = strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				return nil, ErrAllowedHosts
			}
		}
		for _, o := range own {
			if o.host == host && (n == 0 || n == o.port) {
				return nil, ErrOwnHost
			}
		}
		h := host
		if isAddr && addr.Is6() {
			h = "[" + host + "]"
		}
		if n != 0 {
			h += ":" + strconv.Itoa(n)
		}
		if slices.Contains(out, h) {
			return nil, ErrAllowedHosts
		}
		out = append(out, h)
	}
	return out, nil
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// cleartextScheme starts a Spec's explicit http host.
const cleartextScheme = "http://"

// Spec is what a catalog server matches (D221, HR-585). Nothing here is
// fuzzy: no similarity, no wildcard, no name. A similar host, a longer path
// segment or another digest is simply another server.
type Spec struct {
	// Host is the URL host in lower case, with its port unless that is 443.
	// It means https: a bare host is https on 443 (D259). http://addr:port is
	// the one way to name http, for a private or loopback address literal,
	// where a connection may use it, and always with its port (D266).
	Host string
	// PathPrefix is whole path segments under Host; empty is every path.
	PathPrefix string
	// ImageDigest is sha256:<hex>.
	ImageDigest string
	// PackageRef is a package reference as a scan reports it, or the name of
	// a tool package of the org.
	PackageRef string
}

// Normalize validates s and returns its canonical form. Case and the default
// port are the only things it folds; anything else stays as written or is
// refused.
func (s Spec) Normalize() (Spec, error) {
	s.Host = strings.ToLower(s.Host)
	cleartext := strings.HasPrefix(s.Host, cleartextScheme)
	if cleartext {
		host, ok := cleartextHost(strings.TrimPrefix(s.Host, cleartextScheme))
		if !ok {
			return Spec{}, ErrMatch
		}
		s.Host = cleartextScheme + host
	} else {
		s.Host = strings.TrimSuffix(s.Host, ":443")
	}
	if s.PathPrefix != "" && s.PathPrefix != "/" {
		s.PathPrefix = strings.TrimSuffix(s.PathPrefix, "/")
	}
	switch {
	case s.Host == "" && s.ImageDigest == "" && s.PackageRef == "":
		return Spec{}, ErrMatch
	case s.Host != "" && !cleartext && !hostRE.MatchString(s.Host) && !ipv6RE.MatchString(s.Host):
		return Spec{}, ErrMatch
	case s.PathPrefix != "" && (s.Host == "" || !prefixRE.MatchString(s.PathPrefix) || !cleanPath(s.PathPrefix)):
		return Spec{}, ErrMatch
	case s.ImageDigest != "" && !imageRE.MatchString(s.ImageDigest):
		return Spec{}, ErrMatch
	case s.PackageRef != "" && !packRE.MatchString(s.PackageRef):
		return Spec{}, ErrMatch
	}
	return s, nil
}

// Candidate is what is really running, by what identifies it: a connection
// by its URL or its image, a scan by what it saw. A connection's tool package
// is no part of its identity, so a package reference never lets a connection
// through to a URL nobody approved.
type Candidate struct {
	Host, Path, ImageDigest, PackageRef string
	// Cleartext marks a URL over http. A host in a Spec means https, so only
	// the explicit http form matches it (D259, D266).
	Cleartext bool
	// Unmatchable marks something that cannot be read safely: it matches
	// nothing.
	Unmatchable bool
}

// URLCandidate reads a URL the way the catalog compares it: https on its
// effective port, as a Spec's host means it, so https's default port goes
// (D259). http stays apart, whatever its port. A URL with credentials, or one
// this cannot parse, matches nothing.
func URLCandidate(raw string) Candidate {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return Candidate{Unmatchable: true}
	}
	host := strings.ToLower(u.Host)
	if u.Scheme == "https" {
		host = strings.TrimSuffix(host, ":443")
	}
	return Candidate{Host: host, Path: u.EscapedPath(), Cleartext: u.Scheme == "http"}
}

// ImageCandidate reads a container image: repo@sha256:<hex> or sha256:<hex>.
func ImageCandidate(image string) Candidate {
	if _, digest, ok := strings.Cut(image, "@"); ok {
		image = digest
	}
	if !imageRE.MatchString(image) {
		return Candidate{Unmatchable: true}
	}
	return Candidate{ImageDigest: image}
}

// cleanPath reports whether a path means what it says: no escapes and no
// dot segments, so it cannot walk out of a prefix.
func cleanPath(p string) bool {
	if strings.ContainsAny(p, "%\\") {
		return false
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// underPrefix reports whether path is prefix or below it, on a segment
// boundary: /mcp covers /mcp and /mcp/x, never /mcp-evil.
func underPrefix(path, prefix string) bool {
	if prefix == "" {
		return true
	}
	if !cleanPath(path) {
		return false
	}
	return prefix == "/" || path == prefix || strings.HasPrefix(path, prefix+"/")
}

// cleartextHost reads the host of the explicit http form: a private or
// loopback address literal with its port, which is where a connection may use
// http at all. It returns the canonical form.
func cleartextHost(h string) (string, bool) {
	ap, err := netip.ParseAddrPort(h)
	if err != nil || ap.Port() == 0 {
		return "", false
	}
	a := ap.Addr()
	if a.Is4In6() || a.Zone() != "" || (!a.IsPrivate() && !a.IsLoopback()) {
		return "", false
	}
	return ap.String(), true
}

// endpoint splits a host in a URL's form into its name and port: a host with
// no port gets def.
func endpoint(host, def string) (name, port string) {
	if h, p, err := net.SplitHostPort(host); err == nil {
		return h, p
	}
	return strings.Trim(host, "[]"), def
}

// sameEndpoint reports whether c reaches s's host and effective port, over
// either scheme: a bare host covers 443 and 80, because it says no port.
func (s Spec) sameEndpoint(c Candidate) bool {
	def := "443"
	if c.Cleartext {
		def = "80"
	}
	name, port := endpoint(c.Host, def)
	want, wantPort := endpoint(strings.TrimPrefix(s.Host, cleartextScheme), "")
	if name == "" || name != want {
		return false
	}
	return port == wantPort || (wantPort == "" && (port == "443" || port == "80"))
}

// Denies reports whether a decision against s covers c. It is wider than
// Matches, on purpose: a denial must not be escaped by changing the scheme or
// spelling the port, while an approval stays exact (D259, D266).
func (s Spec) Denies(c Candidate) bool {
	if c.Unmatchable {
		return false
	}
	return s.Matches(c) || (s.Host != "" && s.sameEndpoint(c) && underPrefix(c.Path, s.PathPrefix))
}

// matchesHost is Matches for a URL: the explicit http form over http alone, on
// that port, and any other host over https alone.
func (s Spec) matchesHost(c Candidate) bool {
	if want, ok := strings.CutPrefix(s.Host, cleartextScheme); ok {
		name, port := endpoint(c.Host, "80")
		return c.Cleartext && net.JoinHostPort(name, port) == net.JoinHostPort(endpoint(want, ""))
	}
	return !c.Cleartext && c.Host == s.Host
}

// Matches reports whether c is exactly what s names (HR-585).
func (s Spec) Matches(c Candidate) bool {
	if c.Unmatchable {
		return false
	}
	switch {
	case s.Host != "" && s.matchesHost(c) && underPrefix(c.Path, s.PathPrefix):
		return true
	case s.ImageDigest != "" && c.ImageDigest == s.ImageDigest:
		return true
	case s.PackageRef != "" && c.PackageRef == s.PackageRef:
		return true
	}
	return false
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"net/url"
	"strings"
)

// Spec is what a catalogue server matches (D221, HR-585). Nothing here is
// fuzzy: no similarity, no wildcard, no name. A similar host, a longer path
// segment or another digest is simply another server.
type Spec struct {
	// Host is the URL host in lower case, with its port unless that is 443.
	// It means https: a bare host is https on 443 (D259).
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
	s.Host = strings.TrimSuffix(strings.ToLower(s.Host), ":443")
	if s.PathPrefix != "" && s.PathPrefix != "/" {
		s.PathPrefix = strings.TrimSuffix(s.PathPrefix, "/")
	}
	switch {
	case s.Host == "" && s.ImageDigest == "" && s.PackageRef == "":
		return Spec{}, ErrMatch
	case s.Host != "" && !hostRE.MatchString(s.Host) && !ipv6RE.MatchString(s.Host):
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
	// Cleartext marks a URL over http. A host in a Spec means https, so it
	// matches no Spec's host (D259).
	Cleartext bool
	// Unmatchable marks something that cannot be read safely: it matches
	// nothing.
	Unmatchable bool
}

// URLCandidate reads a URL the way the catalogue compares it: https on its
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

// Matches reports whether c is exactly what s names (HR-585).
func (s Spec) Matches(c Candidate) bool {
	if c.Unmatchable {
		return false
	}
	switch {
	case s.Host != "" && !c.Cleartext && c.Host == s.Host && underPrefix(c.Path, s.PathPrefix):
		return true
	case s.ImageDigest != "" && c.ImageDigest == s.ImageDigest:
		return true
	case s.PackageRef != "" && c.PackageRef == s.PackageRef:
		return true
	}
	return false
}

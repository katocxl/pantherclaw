// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the shared threat-intel feed (G0 M38 D1103..D1105;
// FD13, FQ38-2; HR-817..822): its format, its signature, the text
// normalization and shingles its hashes are made with, and matching.
//
// The feed is a compact JWS signed offline by the intel root, separate from
// the package and Hub roots: its typ header is its own and its kid starts
// with RootKIDPrefix, so a feed never verifies as another document, or the
// reverse. The development intel key's kid starts with DevKIDPrefix:
// ParseRoots never accepts it, and only a server on loopback adds it.
//
// An indicator is a hash and nothing else (HR-818): a server's name and
// version, a tool description, or 8-word shingles of injection text, each
// normalized and hashed with SHA-256. A match is inference about a known
// hash, never proof that something else is benign.
package domain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// Feed format (D1103).
const (
	// JOSEType is the JWS typ of a feed.
	JOSEType = "pc-intel-feed+jwt"
	// Spec is the payload's spec.
	Spec = "pc-intel/1"
	// RootKIDPrefix starts every intel root kid.
	RootKIDPrefix = "intel-root-"
	// DevKIDPrefix starts the kid of the development intel key.
	DevKIDPrefix = "intel-dev-"
	// MaxValidity is the longest a feed may run.
	MaxValidity = 30 * 24 * time.Hour
	// MaxFeedBytes bounds a signed feed.
	MaxFeedBytes = 8 << 20
	// MaxIndicators bounds a feed's indicators.
	MaxIndicators = 20000
	// MaxShingles bounds an injection_text indicator's shingles.
	MaxShingles = 64
	// MaxTechniques bounds an indicator's techniques.
	MaxTechniques = 16
	// MaxSummary bounds an indicator's summary, in characters.
	MaxSummary = 280
)

// Kind is what an indicator is a hash of.
type Kind string

// Indicator kinds.
const (
	KindMCPServer       Kind = "mcp_server"
	KindToolDescription Kind = "tool_description"
	KindInjectionText   Kind = "injection_text"
)

// Valid reports whether k is a kind.
func (k Kind) Valid() bool {
	return k == KindMCPServer || k == KindToolDescription || k == KindInjectionText
}

// Severity of an indicator.
type Severity string

// Severities.
const (
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

// Valid reports whether s is a severity.
func (s Severity) Valid() bool { return s == SeverityLow || s == SeverityMedium || s == SeverityHigh }

// The verification errors: each maps to one stable code.
var (
	// ErrSignature: the feed does not verify, or is not a feed.
	ErrSignature = errors.New("intel: signature")
	// ErrExpired: the feed is past its expiry.
	ErrExpired = errors.New("intel: expired")
	// ErrRollback: a lower feed version, or another feed under the same one.
	ErrRollback = errors.New("intel: rollback")
	// ErrNoRoot: nothing is trusted to sign a feed.
	ErrNoRoot = errors.New("intel: no root")
	// ErrFormat: the feed's payload breaks its format.
	ErrFormat = errors.New("intel: format")
)

var (
	indicatorID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	hexDigest   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	technique   = regexp.MustCompile(`^(T[0-9]{4}(\.[0-9]{3})?|AML\.T[0-9]{4}(\.[0-9]{3})?)$`)
)

// ValidID reports whether id is an indicator id.
func ValidID(id string) bool { return indicatorID.MatchString(id) }

// ValidTechnique reports whether t is an ATT&CK or ATLAS technique id.
func ValidTechnique(t string) bool { return technique.MatchString(t) }

// Indicator is one shared indicator: hashes only (HR-818).
type Indicator struct {
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	// SHA256 is the hex hash of mcp_server and tool_description.
	SHA256 string `json:"sha256,omitzero"`
	// Shingles are the hex hashes of injection_text's shingles.
	Shingles   []string `json:"shingles,omitzero"`
	Severity   Severity `json:"severity"`
	Techniques []string `json:"techniques,omitzero"`
	// FirstSeen is a date, YYYY-MM-DD.
	FirstSeen string `json:"first_seen"`
	Summary   string `json:"summary"`
}

// Validate checks one indicator.
func (x Indicator) Validate() error {
	switch {
	case !ValidID(x.ID):
		return fmt.Errorf("indicator id %q is not well formed", x.ID)
	case !x.Kind.Valid():
		return fmt.Errorf("indicator %s: kind %q is not one of mcp_server, tool_description, injection_text", x.ID, x.Kind)
	case !x.Severity.Valid():
		return fmt.Errorf("indicator %s: severity %q is not LOW, MEDIUM or HIGH", x.ID, x.Severity)
	case len(x.Techniques) > MaxTechniques:
		return fmt.Errorf("indicator %s: more than %d techniques", x.ID, MaxTechniques)
	case !utf8.ValidString(x.Summary) || utf8.RuneCountInString(x.Summary) > MaxSummary:
		return fmt.Errorf("indicator %s: the summary is over %d characters", x.ID, MaxSummary)
	}
	if _, err := time.Parse(time.DateOnly, x.FirstSeen); err != nil {
		return fmt.Errorf("indicator %s: first_seen is not a date", x.ID)
	}
	for _, t := range x.Techniques {
		if !ValidTechnique(t) {
			return fmt.Errorf("indicator %s: technique %q is not an ATT&CK or ATLAS id", x.ID, t)
		}
	}
	if x.Kind == KindInjectionText {
		if x.SHA256 != "" || len(x.Shingles) == 0 || len(x.Shingles) > MaxShingles {
			return fmt.Errorf("indicator %s: injection_text carries 1 to %d shingles and no sha256", x.ID, MaxShingles)
		}
		for _, s := range x.Shingles {
			if !hexDigest.MatchString(s) {
				return fmt.Errorf("indicator %s: a shingle is not a hex SHA-256", x.ID)
			}
		}
		return nil
	}
	if !hexDigest.MatchString(x.SHA256) || len(x.Shingles) != 0 {
		return fmt.Errorf("indicator %s: %s carries one hex sha256 and no shingles", x.ID, x.Kind)
	}
	return nil
}

// Feed is the signed payload.
type Feed struct {
	Spec       string      `json:"spec"`
	Version    uint64      `json:"version"`
	Issued     string      `json:"issued"`
	Expires    string      `json:"expires"`
	Indicators []Indicator `json:"indicators"`
}

// Validate checks the feed's shape and returns its issue and expiry times.
func (f Feed) Validate() (time.Time, time.Time, error) {
	if f.Spec != Spec {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: spec %q is not %s", ErrFormat, f.Spec, Spec)
	}
	if f.Version < 1 {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: version must be at least 1", ErrFormat)
	}
	iss, err := time.Parse(time.RFC3339, f.Issued)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: issued is not RFC 3339", ErrFormat)
	}
	exp, err := time.Parse(time.RFC3339, f.Expires)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: expires is not RFC 3339", ErrFormat)
	}
	if !exp.After(iss) || exp.Sub(iss) > MaxValidity {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: a feed expires after it is issued, within 30 days", ErrFormat)
	}
	if len(f.Indicators) > MaxIndicators {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: more than %d indicators", ErrFormat, MaxIndicators)
	}
	seen := make(map[string]bool, len(f.Indicators))
	for _, x := range f.Indicators {
		if err := x.Validate(); err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("%w: %w", ErrFormat, err)
		}
		if seen[x.ID] {
			return time.Time{}, time.Time{}, fmt.Errorf("%w: indicator id %s appears twice", ErrFormat, x.ID)
		}
		seen[x.ID] = true
	}
	return iss, exp, nil
}

// Roots are trusted intel keys by kid.
type Roots map[string]ed25519.PublicKey

// RootKID derives the kid of an intel root public key; it equals
// rootkey.KID(rootkey.PurposeIntel, pub).
func RootKID(pub ed25519.PublicKey) string { return RootKIDPrefix + jws.Thumbprint(pub)[:22] }

// DevKID derives the kid of the development intel public key; it equals
// rootkey.KID(rootkey.PurposeDevIntel, pub).
func DevKID(pub ed25519.PublicKey) string { return DevKIDPrefix + jws.Thumbprint(pub)[:22] }

// IsDevKID reports whether kid names a development intel key.
func IsDevKID(kid string) bool { return strings.HasPrefix(kid, DevKIDPrefix) }

func parseKeys(b []byte, kidOf func(ed25519.PublicKey) string) (Roots, error) {
	var doc struct {
		Keys []jws.JWK `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("intel: roots: %w", err)
	}
	roots := Roots{}
	for _, k := range doc.Keys {
		pub, err := k.Key()
		if err != nil {
			return nil, fmt.Errorf("intel: roots: %w", err)
		}
		if k.Kid != kidOf(pub) {
			return nil, fmt.Errorf("intel: roots: kid %q is not %s", k.Kid, kidOf(pub))
		}
		roots[k.Kid] = pub
	}
	return roots, nil
}

// ParseRoots parses a JWKS of intel root keys whose kids are derived from
// the keys themselves.
func ParseRoots(b []byte) (Roots, error) { return parseKeys(b, RootKID) }

// ParseDevKey parses the public JWKS of the development intel key: exactly
// one key, whose kid is the one derived from it.
func ParseDevKey(b []byte) (Roots, error) {
	roots, err := parseKeys(b, DevKID)
	if err != nil {
		return nil, err
	}
	if len(roots) != 1 {
		return nil, errors.New("intel: development key: want exactly one key")
	}
	return roots, nil
}

// Sign produces a signed feed. It runs offline, in pclaw-admin, with the
// intel root or the development intel key.
func Sign(f Feed, signer *jws.Signer) (string, error) {
	if kid, pub := signer.KeyID(), signer.Public(); kid != RootKID(pub) && kid != DevKID(pub) {
		return "", fmt.Errorf("intel: signing key %q is not an intel root or the development intel key", kid)
	}
	f.Spec = Spec
	if _, _, err := f.Validate(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(f, json.Deterministic(true))
	if err != nil {
		return "", fmt.Errorf("intel: %w", err)
	}
	doc, err := signer.Sign(JOSEType, payload)
	if err != nil {
		return "", err
	}
	if len(doc) > MaxFeedBytes {
		return "", fmt.Errorf("intel: the signed feed is %d bytes, more than the %d allowed", len(doc), MaxFeedBytes)
	}
	return doc, nil
}

// Verified is a feed whose signature, shape and expiry checked out, with
// the hex SHA-256 of its payload (to detect equivocation).
type Verified struct {
	Feed
	Issued, Expiry time.Time
	Digest         string
	KID            string
}

// Verify checks a signed feed against roots and its expiry at now (HR-817).
func Verify(doc string, roots Roots, now time.Time) (Verified, error) {
	if len(roots) == 0 {
		return Verified{}, fmt.Errorf("%w: no intel root keys are embedded in this build", ErrNoRoot)
	}
	v, err := jws.NewVerifier(JOSEType, roots)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	payload, kid, err := v.WithMaxBytes(MaxFeedBytes).Verify(strings.TrimSpace(doc))
	if err != nil {
		return Verified{}, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	var f Feed
	if err := json.Unmarshal(payload, &f, json.RejectUnknownMembers(true)); err != nil {
		return Verified{}, fmt.Errorf("%w: payload: %w", ErrSignature, err)
	}
	iss, exp, err := f.Validate()
	if err != nil {
		return Verified{}, err
	}
	if !now.Before(exp) {
		return Verified{}, fmt.Errorf("%w: feed version %d expired at %s", ErrExpired, f.Version, f.Expires)
	}
	sum := sha256.Sum256(payload)
	return Verified{Feed: f, Issued: iss, Expiry: exp, Digest: hex.EncodeToString(sum[:]), KID: kid}, nil
}

// State is the last feed accepted.
type State struct {
	Version uint64
	Digest  string
}

// CheckAdvance refuses a feed older than the last accepted version, or
// another feed under the same version (HR-817). A nil last means none was
// accepted before. The same feed again is accepted and changes nothing.
func CheckAdvance(last *State, next Verified) error {
	switch {
	case last == nil:
		return nil
	case next.Version < last.Version:
		return fmt.Errorf("%w: feed version %d is older than the accepted %d", ErrRollback, next.Version, last.Version)
	case next.Version == last.Version && next.Digest != last.Digest:
		return fmt.Errorf("%w: a different feed under version %d", ErrRollback, next.Version)
	}
	return nil
}

// SortedTechniques returns techniques sorted without repeats.
func SortedTechniques(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

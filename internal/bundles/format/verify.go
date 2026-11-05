// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package format

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// Signature types.
const (
	// BundleTyp is bundle.jws's typ.
	BundleTyp = "pc-bundle+jwt"
	// RevocationTyp is a publisher revocation statement's typ (D1083).
	RevocationTyp = "pc-bundle-revocation+jwt"
)

// Signature limits.
const (
	// MaxValidity bounds exp - iat of a bundle signature.
	MaxValidity = 400 * 24 * time.Hour
	// ClockSkew is how far in the future iat may be.
	ClockSkew = 5 * time.Minute
)

// kidRe is a publisher key id: publisher-<publisher>-<thumb22>.
var kidRe = regexp.MustCompile(`^publisher-([a-z][a-z0-9-]{2,31})-([A-Za-z0-9_-]{22})$`)

// KID returns a publisher key's kid: publisher-<publisher>-<the first 22
// characters of its RFC 7638 thumbprint>.
func KID(publisher string, pub ed25519.PublicKey) string {
	return "publisher-" + publisher + "-" + jws.Thumbprint(pub)[:22]
}

// KIDPublisher returns the publisher a kid names.
func KIDPublisher(kid string) (string, bool) {
	m := kidRe.FindStringSubmatch(kid)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Fingerprint is a public key's hex SHA-256: what a person compares when
// pinning a key.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// PinnedKey is a publisher key an org pinned.
type PinnedKey struct {
	Publisher string
	KID       string
	PublicKey ed25519.PublicKey
	// AllowedKinds are the item kinds the pin allows; empty allows all.
	AllowedKinds []Kind
}

// Claims are bundle.jws's claims.
type Claims struct {
	// SHA256 is the hex SHA-256 of the exact bundle.json bytes.
	SHA256    string `json:"sha256"`
	Publisher string `json:"publisher"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// Sign signs bundle.json's exact bytes with a publisher key (pclaw bundle
// sign). The kid must be KID(publisher, key).
func Sign(signer *jws.Signer, manifestBytes []byte, iat, exp time.Time) (string, error) {
	m, err := DecodeManifest(manifestBytes)
	if err != nil {
		return "", err
	}
	if signer.KeyID() != KID(m.Publisher, signer.Public()) {
		return "", fail(ErrSignature, "the key's kid must be %s", KID(m.Publisher, signer.Public()))
	}
	if !exp.After(iat) || exp.Sub(iat) > MaxValidity {
		return "", fail(ErrExpired, "exp must be after iat and at most 400 days later")
	}
	sum := sha256.Sum256(manifestBytes)
	payload, err := json.Marshal(Claims{
		SHA256: hex.EncodeToString(sum[:]), Publisher: m.Publisher, Name: m.Name, Version: m.Version,
		IssuedAt: iat.Unix(), ExpiresAt: exp.Unix(),
	}, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return signer.Sign(BundleTyp, payload)
}

// Verify checks a decoded bundle's signature against the org's pinned keys
// (D1080, D1082, HR-796): the kid is an ACTIVE pin of the bundle's
// publisher, the signature verifies with exactly that key, the claims name
// the manifest's publisher, name and version and the SHA-256 of its exact
// bytes, the signature is within its validity, and the pin allows every
// item kind. pins are the org's ACTIVE pins; a revoked or pending pin must
// never be passed.
func Verify(b Bundle, pins []PinnedKey, now time.Time) error {
	if len(b.ManifestBytes) == 0 || b.Signature == "" {
		return fail(ErrSignature, "no signature")
	}
	kid, typ, err := jws.Unverified(b.Signature)
	if err != nil || typ != BundleTyp {
		return fail(ErrSignature, "bundle.jws is not a %s", BundleTyp)
	}
	i := slices.IndexFunc(pins, func(p PinnedKey) bool { return p.KID == kid && p.Publisher == b.Manifest.Publisher })
	if i < 0 {
		return fail(ErrUnpinned, "%s (%s)", kid, b.Manifest.Publisher)
	}
	pin := pins[i]
	if len(pin.PublicKey) != ed25519.PublicKeySize || KID(pin.Publisher, pin.PublicKey) != kid {
		return fail(ErrUnpinned, "the pin of %s does not hold that key", kid)
	}
	v, err := jws.NewVerifier(BundleTyp, map[string]ed25519.PublicKey{kid: pin.PublicKey})
	if err != nil {
		return fail(ErrSignature, "%v", err)
	}
	payload, _, err := v.Verify(b.Signature)
	if err != nil {
		return fail(ErrSignature, "%v", err)
	}
	var c Claims
	if err := json.Unmarshal(payload, &c, json.RejectUnknownMembers(true)); err != nil {
		return fail(ErrSignature, "claims: %v", err)
	}
	sum := sha256.Sum256(b.ManifestBytes)
	want := hex.EncodeToString(sum[:])
	switch {
	case subtle.ConstantTimeCompare([]byte(c.SHA256), []byte(want)) != 1:
		return fail(ErrSignature, "the signature covers another bundle.json")
	case c.Publisher != b.Manifest.Publisher || c.Name != b.Manifest.Name || c.Version != b.Manifest.Version:
		return fail(ErrSignature, "the claims name %s %s@%s", c.Publisher, c.Name, c.Version)
	}
	iat, exp := time.Unix(c.IssuedAt, 0), time.Unix(c.ExpiresAt, 0)
	switch {
	case c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt || exp.Sub(iat) > MaxValidity:
		return fail(ErrExpired, "exp must be after iat and at most 400 days later")
	case iat.After(now.Add(ClockSkew)):
		return fail(ErrExpired, "issued in the future")
	case !now.Before(exp):
		return fail(ErrExpired, "expired at %s", exp.UTC().Format(time.RFC3339))
	}
	if len(pin.AllowedKinds) > 0 {
		for _, k := range b.Kinds() {
			if !slices.Contains(pin.AllowedKinds, k) {
				return fail(ErrKindNotPinned, "%s", k)
			}
		}
	}
	return nil
}

// Revocation scopes (D1083).
const (
	ScopeKey    = "KEY"
	ScopeBundle = "BUNDLE"
)

// Revocation is a publisher-signed revocation statement: either one of the
// publisher's keys (scope KEY, Kid) or a bundle's versions up to and
// including MaxVersion (scope BUNDLE, Name).
type Revocation struct {
	Publisher  string `json:"publisher"`
	Scope      string `json:"scope"`
	Kid        string `json:"kid,omitzero"`
	Name       string `json:"name,omitzero"`
	MaxVersion string `json:"max_version,omitzero"`
	IssuedAt   int64  `json:"iat"`
}

// Check validates a revocation's claims by themselves.
func (r Revocation) Check() error {
	switch {
	case !ValidPublisher(r.Publisher):
		return fail(ErrRevocation, "publisher %q", r.Publisher)
	case r.IssuedAt <= 0:
		return fail(ErrRevocation, "iat is required")
	}
	switch r.Scope {
	case ScopeKey:
		if pub, ok := KIDPublisher(r.Kid); !ok || pub != r.Publisher || r.Name != "" || r.MaxVersion != "" {
			return fail(ErrRevocation, "a KEY revocation names one kid of its publisher and nothing else")
		}
	case ScopeBundle:
		if !ValidBundleName(r.Publisher, r.Name) || !ValidVersion(r.MaxVersion) || r.Kid != "" {
			return fail(ErrRevocation, "a BUNDLE revocation names one bundle of its publisher and a max_version")
		}
	default:
		return fail(ErrRevocation, "scope %q", r.Scope)
	}
	return nil
}

// SignRevocation signs a revocation statement with a publisher key.
func SignRevocation(signer *jws.Signer, r Revocation) (string, error) {
	if err := r.Check(); err != nil {
		return "", err
	}
	if signer.KeyID() != KID(r.Publisher, signer.Public()) {
		return "", fail(ErrRevocation, "the key's kid must be %s", KID(r.Publisher, signer.Public()))
	}
	payload, err := json.Marshal(r, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return signer.Sign(RevocationTyp, payload)
}

// VerifiedRevocation is a revocation statement that verified.
type VerifiedRevocation struct {
	Revocation
	// SignedBy is the kid that signed it.
	SignedBy string
	// SHA256 is the hex SHA-256 of the statement's canonical compact form,
	// which identifies it (one statement is applied once).
	SHA256 string
}

// VerifyRevocation checks a revocation statement (D1083, HR-800): it is
// accepted only when signed by a key the org has pinned for that publisher,
// in any state (a revoked key may still revoke). keys are every pin the
// org has ever made for the statement's publisher.
func VerifyRevocation(compact string, keys []PinnedKey, now time.Time) (VerifiedRevocation, error) {
	var out VerifiedRevocation
	compact = strings.TrimSpace(compact)
	kid, typ, err := jws.Unverified(compact)
	if err != nil || typ != RevocationTyp {
		return out, fail(ErrRevocation, "not a %s", RevocationTyp)
	}
	publisher, ok := KIDPublisher(kid)
	if !ok {
		return out, fail(ErrRevocation, "kid %q is not a publisher key", kid)
	}
	set := map[string]ed25519.PublicKey{}
	for _, k := range keys {
		if k.Publisher == publisher && k.KID == kid && len(k.PublicKey) == ed25519.PublicKeySize && KID(k.Publisher, k.PublicKey) == kid {
			set[kid] = k.PublicKey
		}
	}
	if len(set) == 0 {
		return out, fail(ErrUnpinned, "%s was never pinned", kid)
	}
	v, err := jws.NewVerifier(RevocationTyp, set)
	if err != nil {
		return out, fail(ErrRevocation, "%v", err)
	}
	payload, _, err := v.Verify(compact)
	if err != nil {
		return out, fail(ErrRevocation, "%v", err)
	}
	var r Revocation
	if err := json.Unmarshal(payload, &r, json.RejectUnknownMembers(true)); err != nil {
		return out, fail(ErrRevocation, "claims: %v", err)
	}
	if err := r.Check(); err != nil {
		return out, err
	}
	if r.Publisher != publisher {
		return out, fail(ErrRevocation, "signed by %s for %s", kid, r.Publisher)
	}
	if time.Unix(r.IssuedAt, 0).After(now.Add(ClockSkew)) {
		return out, fail(ErrRevocation, "issued in the future")
	}
	canon, ok := jws.Canonical(compact)
	if !ok {
		return out, errors.New("bundle: revocation: not canonical")
	}
	sum := sha256.Sum256([]byte(canon))
	return VerifiedRevocation{Revocation: r, SignedBy: kid, SHA256: hex.EncodeToString(sum[:])}, nil
}

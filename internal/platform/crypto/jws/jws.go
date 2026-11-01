// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package jws signs and verifies compact JWS objects with Ed25519 (EdDSA)
// only (PAP-1 §2, ADR-0012, HR-095).
//
// Verification is pinned: the algorithm list is exactly {EdDSA}, the key is
// looked up by kid in a fixed set (never taken from the token: embedded jwk,
// jku, x5u and x5c headers are rejected), the typ header must equal the
// expected type, and critical headers (including b64=false) are rejected.
package jws

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// MaxCompactBytes caps the size of a compact JWS accepted for verification.
const MaxCompactBytes = 64 << 10

var (
	// ErrInvalid is returned for every verification failure. The wrapped
	// detail is for logs; callers must treat all causes the same way.
	ErrInvalid = errors.New("jws: invalid signature or token")

	allowed = []jose.SignatureAlgorithm{jose.EdDSA}
)

// Signer signs payloads with one Ed25519 key.
type Signer struct {
	kid  string
	priv ed25519.PrivateKey
}

// NewSigner returns a Signer for priv identified by kid.
func NewSigner(kid string, priv ed25519.PrivateKey) (*Signer, error) {
	if kid == "" || len(kid) > 128 {
		return nil, errors.New("jws: kid must be 1..128 bytes")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("jws: invalid Ed25519 private key")
	}
	return &Signer{kid: kid, priv: priv}, nil
}

// KeyID returns the signer's kid.
func (s *Signer) KeyID() string { return s.kid }

// Public returns the signer's public key.
func (s *Signer) Public() ed25519.PublicKey {
	pub, _ := s.priv.Public().(ed25519.PublicKey)
	return pub
}

// Sign returns a compact JWS with protected header {alg:EdDSA, kid, typ}.
func (s *Signer) Sign(typ string, payload []byte) (string, error) {
	if typ == "" {
		return "", errors.New("jws: typ is required")
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: s.priv, KeyID: s.kid}},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)),
	)
	if err != nil {
		return "", fmt.Errorf("jws: signer: %w", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("jws: sign: %w", err)
	}
	return obj.CompactSerialize()
}

// Verifier verifies tokens of one type against a pinned set of keys.
type Verifier struct {
	typ  string
	keys map[string]ed25519.PublicKey
	max  int
}

// NewVerifier returns a Verifier that accepts only tokens whose typ header
// equals typ and whose kid is in keys.
func NewVerifier(typ string, keys map[string]ed25519.PublicKey) (*Verifier, error) {
	if typ == "" {
		return nil, errors.New("jws: typ is required")
	}
	for kid, k := range keys {
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("jws: invalid Ed25519 public key for kid %q", kid)
		}
	}
	return &Verifier{typ: typ, keys: maps.Clone(keys), max: MaxCompactBytes}, nil
}

// WithMaxBytes returns a copy of v accepting tokens of at most n bytes
// instead of MaxCompactBytes, for a signed document larger than a token (the
// Hub index, G0 M23 D100).
func (v *Verifier) WithMaxBytes(n int) *Verifier {
	out := *v
	out.max = n
	return &out
}

// header is the only protected header shape we accept. Any other member
// (jwk, jku, x5u, x5c, crit, b64, zip, cty, …) makes the token invalid, so
// keys can never come from the token itself.
type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Verify checks the token and returns its payload and kid.
func (v *Verifier) Verify(compact string) (payload []byte, kid string, err error) {
	h, err := parseHeader(compact, v.max)
	if err != nil {
		return nil, "", err
	}
	if h.Alg != string(jose.EdDSA) {
		return nil, "", fmt.Errorf("%w: algorithm %q not allowed", ErrInvalid, h.Alg)
	}
	if h.Typ != v.typ {
		return nil, "", fmt.Errorf("%w: typ %q, want %q", ErrInvalid, h.Typ, v.typ)
	}
	key, ok := v.keys[h.Kid]
	if !ok {
		return nil, "", fmt.Errorf("%w: unknown kid %q", ErrInvalid, h.Kid)
	}
	// Only the canonical encoding is accepted, so one token has one string.
	if c, ok := Canonical(compact); !ok || c != compact {
		return nil, "", fmt.Errorf("%w: non-canonical encoding", ErrInvalid)
	}
	obj, err := jose.ParseSignedCompact(compact, allowed)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if len(obj.Signatures) != 1 {
		return nil, "", fmt.Errorf("%w: expected one signature", ErrInvalid)
	}
	payload, err = obj.Verify(key)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return payload, h.Kid, nil
}

// Canonical returns compact with each of its three segments re-encoded as
// canonical unpadded base64url, and false when it is not three decodable
// segments. Base64 decoders (go-jose's among them) ignore the unused low
// bits of a segment's last character, so several strings verify as the same
// signed token: a single-use key taken from the string must be taken from
// this form (HR-143, HR-145).
func Canonical(compact string) (string, bool) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return "", false
	}
	for i, p := range parts {
		raw, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			return "", false
		}
		parts[i] = base64.RawURLEncoding.EncodeToString(raw)
	}
	return strings.Join(parts, "."), true
}

// Unverified returns the kid and typ of a token without verifying it, for
// routing to the right verifier. Never trust anything else from it.
func Unverified(compact string) (kid, typ string, err error) {
	h, err := parseHeader(compact, MaxCompactBytes)
	if err != nil {
		return "", "", err
	}
	return h.Kid, h.Typ, nil
}

func parseHeader(compact string, maxBytes int) (header, error) {
	var h header
	if len(compact) > maxBytes || strings.ContainsAny(compact, " \t\r\n") || strings.Count(compact, ".") != 2 {
		return h, fmt.Errorf("%w: malformed compact serialization", ErrInvalid)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(compact[:strings.IndexByte(compact, '.')])
	if err != nil {
		return h, fmt.Errorf("%w: header encoding", ErrInvalid)
	}
	if err := json.Unmarshal(raw, &h, json.RejectUnknownMembers(true)); err != nil {
		return h, fmt.Errorf("%w: header: %w", ErrInvalid, err)
	}
	if h.Kid == "" || h.Typ == "" {
		return h, fmt.Errorf("%w: kid and typ are required", ErrInvalid)
	}
	return h, nil
}

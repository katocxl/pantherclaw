// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package sdjwt verifies Selective Disclosure JWTs (RFC 9901) for agent
// payment mandates (G0 M39 D1122; HR-830, HR-833). It verifies and never
// issues: there is no signing code here (FQ39-1).
//
// The rules, all fail closed:
//
//   - a presentation is <issuer-jwt>~<disclosure>~…~<kb-jwt or empty>;
//   - JWTs are ES256 (P-256) or EdDSA (Ed25519) only, never none, HS* or
//     RSA; their protected header holds only alg, kid and typ, so a key
//     never comes from the token (no jwk, jku, x5u, x5c or crit);
//   - _sd_alg is sha-256 or absent; every disclosure is referenced exactly
//     once, a disclosed name is never _sd or "..." and never overwrites a
//     claim, and digests that match no disclosure are decoys;
//   - a KB-JWT has typ kb+jwt, is signed by the cnf.jwk key, and carries
//     aud, nonce, iat no older than 5 minutes and sd_hash over the
//     presentation it ends.
package sdjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// Limits and parameters.
const (
	// MaxPresentation bounds one presentation.
	MaxPresentation = 32 << 10
	// MaxDisclosures bounds the disclosures of one presentation.
	MaxDisclosures = 128
	// MaxDepth bounds the nesting of a payload.
	MaxDepth = 16
	// KBMaxAge is how old a KB-JWT's iat may be (D1122).
	KBMaxAge = 5 * time.Minute
	// ClockSkew is how far in the future an iat may be.
	ClockSkew = 30 * time.Second
	// HashAlg is the only _sd_alg accepted.
	HashAlg = "sha-256"
	// TypKB is the KB-JWT typ (RFC 9901 §4.3).
	TypKB = "kb+jwt"
)

// Algorithms.
const (
	AlgES256 = "ES256"
	AlgEdDSA = "EdDSA"
)

var allowedAlgs = []jose.SignatureAlgorithm{jose.ES256, jose.EdDSA}

// ErrInvalid is returned for every verification failure. The wrapped
// detail is for logs; callers treat all causes the same way.
var ErrInvalid = errors.New("sdjwt: invalid presentation")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Header is the protected header of a JWT this package accepts.
type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

// Presentation is a parsed, not yet verified, SD-JWT presentation.
type Presentation struct {
	// IssuerJWT is the issuer-signed JWT in canonical encoding.
	IssuerJWT string
	// Disclosures are the disclosures as presented.
	Disclosures []string
	// KB is the KB-JWT, empty when none.
	KB string
	// Header is the issuer JWT's header.
	Header Header
}

// Parse splits a presentation. It verifies nothing.
func Parse(s string) (*Presentation, error) {
	if len(s) > MaxPresentation || strings.ContainsAny(s, " \t\r\n") {
		return nil, invalid("size or whitespace")
	}
	parts := strings.Split(s, "~")
	if len(parts) < 2 {
		return nil, invalid("no ~ separator")
	}
	if len(parts)-2 > MaxDisclosures {
		return nil, invalid("too many disclosures")
	}
	jwt, ok := jws.Canonical(parts[0])
	if !ok || jwt != parts[0] {
		return nil, invalid("issuer JWT encoding")
	}
	h, err := HeaderOf(jwt)
	if err != nil {
		return nil, err
	}
	p := &Presentation{IssuerJWT: jwt, Header: h, KB: parts[len(parts)-1]}
	for _, d := range parts[1 : len(parts)-1] {
		if d == "" {
			return nil, invalid("empty disclosure")
		}
		p.Disclosures = append(p.Disclosures, d)
	}
	if p.KB != "" {
		if kb, ok := jws.Canonical(p.KB); !ok || kb != p.KB {
			return nil, invalid("KB-JWT encoding")
		}
	}
	return p, nil
}

// WithoutKB returns the presentation up to and including the last ~, the
// input of sd_hash (RFC 9901 §4.3.1).
func (p *Presentation) WithoutKB() string {
	var b strings.Builder
	b.WriteString(p.IssuerJWT)
	b.WriteByte('~')
	for _, d := range p.Disclosures {
		b.WriteString(d)
		b.WriteByte('~')
	}
	return b.String()
}

// Canonical returns the presentation with its KB-JWT, as verified.
func (p *Presentation) Canonical() string { return p.WithoutKB() + p.KB }

// Digest returns base64url(SHA-256(ASCII(s))), the digest of a disclosure
// and the form of sd_hash.
func Digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// HeaderOf decodes a JWT's protected header, accepting only alg, kid and
// typ, and an allowed alg.
func HeaderOf(compact string) (Header, error) {
	var h Header
	seg, _, ok := strings.Cut(compact, ".")
	if !ok || strings.Count(compact, ".") != 2 {
		return h, invalid("malformed JWT")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(seg)
	if err != nil {
		return h, invalid("header encoding")
	}
	if err := json.Unmarshal(raw, &h, json.RejectUnknownMembers(true)); err != nil {
		return h, invalid("header members: %v", err)
	}
	if h.Alg != AlgES256 && h.Alg != AlgEdDSA {
		return h, invalid("algorithm %q not allowed", h.Alg)
	}
	return h, nil
}

// Fits reports whether key can verify alg: ES256 needs a P-256 key and
// EdDSA an Ed25519 key.
func Fits(key crypto.PublicKey, alg string) bool {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return alg == AlgES256 && k.Curve == elliptic.P256()
	case ed25519.PublicKey:
		return alg == AlgEdDSA && len(k) == ed25519.PublicKeySize
	}
	return false
}

// VerifyJWT verifies compact with key and returns its payload. typ must be
// one of typs (an empty typs accepts any or none).
func VerifyJWT(compact string, typs []string, key crypto.PublicKey) ([]byte, Header, error) {
	h, err := HeaderOf(compact)
	if err != nil {
		return nil, h, err
	}
	if len(typs) > 0 && !slices.Contains(typs, h.Typ) {
		return nil, h, invalid("typ %q", h.Typ)
	}
	if !Fits(key, h.Alg) {
		return nil, h, invalid("key does not fit %s", h.Alg)
	}
	if c, ok := jws.Canonical(compact); !ok || c != compact {
		return nil, h, invalid("non-canonical encoding")
	}
	obj, err := jose.ParseSignedCompact(compact, allowedAlgs)
	if err != nil || len(obj.Signatures) != 1 {
		return nil, h, invalid("parse")
	}
	payload, err := obj.Verify(key)
	if err != nil {
		return nil, h, invalid("signature")
	}
	return payload, h, nil
}

// PublicKey reads a public JWK (a cnf.jwk or a JWKS member): EC P-256 or
// OKP Ed25519 only. Private members are refused.
func PublicKey(raw []byte) (crypto.PublicKey, string, error) {
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, "", invalid("jwk")
	}
	if _, private := probe["d"]; private {
		return nil, "", invalid("jwk has private members")
	}
	var k jose.JSONWebKey
	if err := k.UnmarshalJSON(raw); err != nil || !k.IsPublic() {
		return nil, "", invalid("jwk")
	}
	switch pub := k.Key.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() || (k.Algorithm != "" && k.Algorithm != AlgES256) {
			return nil, "", invalid("jwk curve or alg")
		}
		return pub, k.KeyID, nil
	case ed25519.PublicKey:
		if k.Algorithm != "" && k.Algorithm != AlgEdDSA && k.Algorithm != "Ed25519" {
			return nil, "", invalid("jwk alg")
		}
		return pub, k.KeyID, nil
	}
	return nil, "", invalid("jwk key type")
}

// Disclose applies the presentation's disclosures to the verified issuer
// payload and returns the processed claims (RFC 9901 §7.1), without _sd,
// _sd_alg or decoys.
func (p *Presentation) Disclose(payload []byte) (map[string]any, error) {
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil || claims == nil {
		return nil, invalid("payload is not an object")
	}
	if a, present := claims["_sd_alg"]; present {
		if s, _ := a.(string); s != HashAlg {
			return nil, invalid("_sd_alg %v", a)
		}
		delete(claims, "_sd_alg")
	}
	d := &discloser{byDigest: map[string]disclosure{}, used: map[string]bool{}}
	for _, raw := range p.Disclosures {
		dg := Digest(raw)
		if _, dup := d.byDigest[dg]; dup {
			return nil, invalid("duplicate disclosure")
		}
		dis, err := decodeDisclosure(raw)
		if err != nil {
			return nil, err
		}
		d.byDigest[dg] = dis
	}
	out, err := d.object(claims, 0)
	if err != nil {
		return nil, err
	}
	if len(d.used) != len(d.byDigest) {
		return nil, invalid("a disclosure is not referenced")
	}
	return out, nil
}

type disclosure struct {
	name  string // empty for an array element
	array bool
	value any
}

func decodeDisclosure(raw string) (disclosure, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil {
		return disclosure{}, invalid("disclosure encoding")
	}
	var arr []any
	if err := json.Unmarshal(b, &arr); err != nil {
		return disclosure{}, invalid("disclosure is not an array")
	}
	if len(arr) == 0 {
		return disclosure{}, invalid("empty disclosure")
	}
	if salt, isString := arr[0].(string); !isString || salt == "" {
		return disclosure{}, invalid("disclosure salt")
	}
	switch len(arr) {
	case 2:
		return disclosure{array: true, value: arr[1]}, nil
	case 3:
		name, ok := arr[1].(string)
		if !ok || name == "_sd" || name == "..." || name == "_sd_alg" {
			return disclosure{}, invalid("disclosure name")
		}
		return disclosure{name: name, value: arr[2]}, nil
	}
	return disclosure{}, invalid("disclosure length")
}

type discloser struct {
	byDigest map[string]disclosure
	used     map[string]bool
}

func (d *discloser) take(dg string) (disclosure, bool, error) {
	dis, found := d.byDigest[dg]
	if !found {
		return disclosure{}, false, nil // a decoy
	}
	if d.used[dg] {
		return disclosure{}, false, invalid("digest referenced twice")
	}
	d.used[dg] = true
	return dis, true, nil
}

func (d *discloser) value(v any, depth int) (any, error) {
	if depth > MaxDepth {
		return nil, invalid("too deep")
	}
	switch t := v.(type) {
	case map[string]any:
		return d.object(t, depth)
	case []any:
		return d.array(t, depth)
	}
	return v, nil
}

func (d *discloser) object(o map[string]any, depth int) (map[string]any, error) {
	out := make(map[string]any, len(o))
	for k, v := range o {
		if k == "_sd" || k == "..." {
			continue
		}
		pv, err := d.value(v, depth+1)
		if err != nil {
			return nil, err
		}
		out[k] = pv
	}
	if raw, present := o["_sd"]; present {
		list, isList := raw.([]any)
		if !isList {
			return nil, invalid("_sd is not an array")
		}
		for _, e := range list {
			dg, isString := e.(string)
			if !isString {
				return nil, invalid("_sd member is not a string")
			}
			dis, found, err := d.take(dg)
			if err != nil {
				return nil, err
			}
			if !found {
				continue
			}
			if dis.array {
				return nil, invalid("array disclosure in _sd")
			}
			if _, exists := out[dis.name]; exists {
				return nil, invalid("disclosed claim %q exists", dis.name)
			}
			pv, err := d.value(dis.value, depth+1)
			if err != nil {
				return nil, err
			}
			out[dis.name] = pv
		}
	}
	if _, present := o["..."]; present {
		return nil, invalid(`"..." member in an object`)
	}
	return out, nil
}

func (d *discloser) array(a []any, depth int) ([]any, error) {
	out := make([]any, 0, len(a))
	for _, e := range a {
		if m, isMap := e.(map[string]any); isMap {
			if ref, present := m["..."]; present {
				if len(m) != 1 {
					return nil, invalid(`"..." element with other members`)
				}
				dg, isString := ref.(string)
				if !isString {
					return nil, invalid(`"..." is not a string`)
				}
				dis, found, err := d.take(dg)
				if err != nil {
					return nil, err
				}
				if !found {
					continue
				}
				if !dis.array {
					return nil, invalid("object disclosure in an array")
				}
				pv, err := d.value(dis.value, depth+1)
				if err != nil {
					return nil, err
				}
				out = append(out, pv)
				continue
			}
		}
		pv, err := d.value(e, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, pv)
	}
	return out, nil
}

// HolderKey returns the key of a cnf claim ({"jwk": {...}}).
func HolderKey(claims map[string]any) (crypto.PublicKey, error) {
	cnf, isMap := claims["cnf"].(map[string]any)
	if !isMap {
		return nil, invalid("no cnf")
	}
	jwk, isMap := cnf["jwk"].(map[string]any)
	if !isMap {
		return nil, invalid("no cnf.jwk")
	}
	raw, err := json.Marshal(jwk)
	if err != nil {
		return nil, invalid("cnf.jwk")
	}
	k, _, err := PublicKey(raw)
	return k, err
}

// KBClaims are a verified KB-JWT's claims.
type KBClaims struct {
	Aud      string
	Nonce    string
	IssuedAt time.Time
	// Extra holds the other claims (AP2 v0.1 transaction_data).
	Extra map[string]jsontext.Value
}

// VerifyKB verifies the presentation's KB-JWT with the holder key (RFC
// 9901 §7.3): typ kb+jwt, aud one of audiences (none: refused, D1122b),
// a nonce, iat within KBMaxAge of now, and sd_hash over the
// presentation.
func (p *Presentation) VerifyKB(holder crypto.PublicKey, audiences []string, now time.Time) (KBClaims, error) {
	if p.KB == "" {
		return KBClaims{}, invalid("no KB-JWT")
	}
	payload, _, err := VerifyJWT(p.KB, []string{TypKB}, holder)
	if err != nil {
		return KBClaims{}, err
	}
	var m map[string]jsontext.Value
	if err := json.Unmarshal(payload, &m); err != nil {
		return KBClaims{}, invalid("KB-JWT payload")
	}
	var c KBClaims
	var sdHash string
	var iat float64
	for k, dst := range map[string]any{"aud": &c.Aud, "nonce": &c.Nonce, "sd_hash": &sdHash, "iat": &iat} {
		v, present := m[k]
		if !present || json.Unmarshal(v, dst) != nil {
			return KBClaims{}, invalid("KB-JWT %s", k)
		}
		delete(m, k)
	}
	if c.Aud == "" || c.Nonce == "" {
		return KBClaims{}, invalid("KB-JWT aud or nonce empty")
	}
	if !slices.Contains(audiences, c.Aud) {
		return KBClaims{}, invalid("KB-JWT aud")
	}
	if sdHash != Digest(p.WithoutKB()) {
		return KBClaims{}, invalid("KB-JWT sd_hash")
	}
	at, err := Fresh(iat, now)
	if err != nil {
		return KBClaims{}, err
	}
	c.IssuedAt, c.Extra = at, m
	return c, nil
}

// Fresh checks a NumericDate iat: an integer no older than KBMaxAge and at
// most ClockSkew ahead of now.
func Fresh(iat float64, now time.Time) (time.Time, error) {
	if iat != math.Trunc(iat) || iat <= 0 || iat > 1<<40 {
		return time.Time{}, invalid("iat")
	}
	at := time.Unix(int64(iat), 0)
	if at.Before(now.Add(-KBMaxAge)) || at.After(now.Add(ClockSkew)) {
		return time.Time{}, invalid("iat outside the window")
	}
	return at, nil
}

// NumericDate reads an optional integer NumericDate claim.
func NumericDate(claims map[string]any, name string) (time.Time, bool, error) {
	v, present := claims[name]
	if !present {
		return time.Time{}, false, nil
	}
	f, isNum := v.(float64)
	if !isNum || f != math.Trunc(f) || f <= 0 || f > 1<<40 {
		return time.Time{}, false, invalid("%s", name)
	}
	return time.Unix(int64(f), 0), true, nil
}

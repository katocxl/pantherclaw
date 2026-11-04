// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pap

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/v2"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// Request is what the verifier itself knows about the HTTP request a proof
// claims to cover. URL must come from the verifier's configured public URL
// plus the request path, never from the Host header (G0 M3 constraint 6);
// BodySHA256 must be computed over the raw bytes before any parsing
// (HR-091).
type Request struct {
	Method     string
	URL        string
	BodySHA256 [32]byte
	// Token is the workload token from "Authorization: PAP <token>"; empty
	// for a key-only proof (PAP-1 §4).
	Token string
}

// Checked is a request whose token (if any) and proof passed every
// stateless check of PAP-1 §4, in order. Only VerifyRequest creates one.
// The caller must still check that the nonce is current and insert
// (JKT, JTI) into the replay store, in that order and only then (HR-090).
type Checked struct {
	token *Token
	key   ed25519.PublicKey
	jkt   string
	jti   string
	nonce string
	iat   time.Time
}

// Token returns the verified workload token, or false for a key-only proof.
func (c Checked) Token() (Token, bool) {
	if c.token == nil {
		return Token{}, false
	}
	return *c.token, true
}

// Key returns the proof key; JKT its RFC 7638 thumbprint.
func (c Checked) Key() ed25519.PublicKey { return c.key }

// JKT returns the proof key's thumbprint.
func (c Checked) JKT() string { return c.jkt }

// JTI returns the proof's unique id.
func (c Checked) JTI() string { return c.jti }

// Nonce returns the server nonce the proof carries; the caller checks that
// it is current.
func (c Checked) Nonce() string { return c.nonce }

// IssuedAt returns the proof's iat.
func (c Checked) IssuedAt() time.Time { return c.iat }

type proofHeader struct {
	Alg string   `json:"alg"`
	Typ string   `json:"typ"`
	JWK proofJWK `json:"jwk"`
}

// proofJWK accepts only the public members of an Ed25519 key: a "d"
// (private key), "kid", "x5c" or anything else is rejected.
type proofJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

type proofClaims struct {
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	JTI   string `json:"jti"`
	ATH   string `json:"ath,omitzero"`
	BH    string `json:"bh"`
	Nonce string `json:"nonce,omitzero"`
}

// VerifyRequest runs PAP-1 §4 steps 1–4 and the shape checks of step 5:
//
//  1. the workload token, when present (signature, iss, aud, exp/nbf);
//  2. the proof signature, with the embedded Ed25519 jwk only;
//  3. jkt(jwk) == cnf.jkt;
//  4. htm, htu, ath and bh;
//  5. the nonce's shape (the caller checks that it is current).
//
// Step 6, the replay insert, belongs to the caller and must follow the
// nonce check.
func VerifyRequest(tokens *jws.Verifier, issuer string, req Request, proof string, now time.Time) (Checked, error) {
	var tok *Token
	if req.Token != "" {
		t, err := VerifyToken(tokens, issuer, req.Token, now)
		if err != nil {
			return Checked{}, err
		}
		tok = &t
	}
	key, c, err := parseProof(proof)
	if err != nil {
		return Checked{}, err
	}
	jkt := jws.Thumbprint(key)
	if tok != nil && subtle.ConstantTimeCompare([]byte(jkt), []byte(tok.JKT)) != 1 {
		return Checked{}, fail(CodeKeyMismatch, "proof key is not the token's key")
	}
	if c.HTM != req.Method || req.Method == "" {
		return Checked{}, fail(CodeInvalidProof, "htm")
	}
	if !sameHTU(c.HTU, req.URL) {
		return Checked{}, fail(CodeInvalidProof, "htu")
	}
	if tok != nil {
		sum := sha256.Sum256([]byte(req.Token))
		if c.ATH != b64(sum[:]) {
			return Checked{}, fail(CodeInvalidProof, "ath")
		}
	} else if c.ATH != "" {
		return Checked{}, fail(CodeInvalidProof, "ath without a token")
	}
	if c.BH != b64(req.BodySHA256[:]) {
		return Checked{}, fail(CodeBodyHashMismatch, "bh")
	}
	iat := time.Unix(c.IAT, 0)
	if iat.After(now.Add(Leeway)) || iat.Before(now.Add(-MaxProofAge)) {
		return Checked{}, fail(CodeInvalidProof, "iat")
	}
	if len(c.JTI) < 22 || len(c.JTI) > 128 || !printableASCII(c.JTI) {
		return Checked{}, fail(CodeInvalidProof, "jti")
	}
	if !ValidNonce(c.Nonce) {
		return Checked{}, fail(CodeUseNonce, "nonce missing or malformed")
	}
	return Checked{token: tok, key: key, jkt: jkt, jti: c.JTI, nonce: c.Nonce, iat: iat}, nil
}

// parseProof checks the proof's header strictly, verifies its signature
// with the embedded key and decodes its claims.
func parseProof(compact string) (ed25519.PublicKey, proofClaims, error) {
	return parseProofOf(compact, ProofType)
}

// parseProofOf is parseProof for a proof of JWS type typ: a PAP/1 proof or
// a DPoP proof (G0 M30 D912), both EdDSA with the embedded public jwk only.
func parseProofOf(compact, typ string) (ed25519.PublicKey, proofClaims, error) {
	var c proofClaims
	if len(compact) > MaxProofBytes || strings.ContainsAny(compact, " \t\r\n") || strings.Count(compact, ".") != 2 {
		return nil, c, fail(CodeInvalidProof, "malformed")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(compact[:strings.IndexByte(compact, '.')])
	if err != nil {
		return nil, c, fail(CodeInvalidProof, "header encoding")
	}
	var h proofHeader
	if err := json.Unmarshal(raw, &h, json.RejectUnknownMembers(true)); err != nil {
		return nil, c, fail(CodeInvalidProof, "header: %v", err)
	}
	if !slices.Contains(ProofAlgorithms, h.Alg) || h.Typ != typ {
		return nil, c, fail(CodeInvalidProof, "alg %q typ %q", h.Alg, h.Typ)
	}
	key, err := jws.JWK{Kty: h.JWK.Kty, Crv: h.JWK.Crv, X: h.JWK.X}.Key()
	if err != nil {
		return nil, c, fail(CodeInvalidProof, "jwk: %v", err)
	}
	obj, err := jose.ParseSignedCompact(compact, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil || len(obj.Signatures) != 1 {
		return nil, c, fail(CodeInvalidProof, "parse")
	}
	payload, err := obj.Verify(key)
	if err != nil {
		return nil, c, fail(CodeInvalidProof, "signature")
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, c, fail(CodeInvalidProof, "claims: %v", err)
	}
	return key, c, nil
}

// sameHTU compares a proof's htu with the verifier's URL: scheme and host
// case-insensitively, the path exactly; query, fragment and userinfo are
// never allowed (PAP-1 §4).
func sameHTU(claimed, want string) bool {
	a, err1 := url.Parse(claimed)
	b, err2 := url.Parse(want)
	if err1 != nil || err2 != nil || claimed == "" || want == "" {
		return false
	}
	for _, u := range []*url.URL{a, b} {
		if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Host == "" ||
			(u.Scheme != "https" && u.Scheme != "http") || u.ForceQuery {
			return false
		}
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host) && a.EscapedPath() == b.EscapedPath()
}

func printableASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

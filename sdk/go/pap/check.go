// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package pap

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ProofRequest is what a verifier knows about the request a proof covers:
// its own URL for it (never one from the Host header), the method, the
// exact body and the workload token sent with it, if any.
type ProofRequest struct {
	Method string
	URL    string
	Body   []byte
	Token  string
}

// CodeError is a refusal with its PAP-Error code.
type CodeError struct{ Code ErrorCode }

func (e *CodeError) Error() string { return "pap: " + string(e.Code) }

func refuse(c ErrorCode) error { return &CodeError{Code: c} }

// Proof checks, in the order of PAP/1 §4.
const (
	maxProofBytes = 8 << 10
	proofLeeway   = 60 * time.Second
	maxProofAge   = 6 * time.Minute
)

var noncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)

// CheckProof checks a PAP-Proof against the request it came with at now,
// as PantherClaw does in steps 2–5 of PAP/1 §4: the header (alg EdDSA, typ,
// a public Ed25519 jwk and nothing else) and signature, the key binding to
// the token's cnf.jkt, htm, htu, ath, bh, iat, jti and the nonce's shape.
// The token itself is not verified here; the replay check and the nonce's
// freshness belong to the server. The error is a *CodeError.
func CheckProof(proof string, r ProofRequest, now time.Time) error {
	key, c, err := parseProof(proof)
	if err != nil {
		return err
	}
	if r.Token != "" {
		claims, err := ParseTokenClaims(r.Token)
		if err != nil {
			return refuse(ErrInvalidToken)
		}
		if Thumbprint(key) != claims.Cnf.JKT {
			return refuse(ErrKeyMismatch)
		}
	}
	switch {
	case r.Method == "" || c.HTM != r.Method || !sameHTU(c.HTU, r.URL):
		return refuse(ErrInvalidProof)
	case r.Token != "" && c.ATH != ATH(r.Token), r.Token == "" && c.ATH != "":
		return refuse(ErrInvalidProof)
	case c.BH != BodyHash(r.Body):
		return refuse(ErrBodyHashMismatch)
	}
	iat := time.Unix(c.IAT, 0)
	if iat.After(now.Add(proofLeeway)) || iat.Before(now.Add(-maxProofAge)) {
		return refuse(ErrInvalidProof)
	}
	if len(c.JTI) < 22 || len(c.JTI) > 128 || !printable(c.JTI) {
		return refuse(ErrInvalidProof)
	}
	if !noncePattern.MatchString(c.Nonce) {
		return refuse(ErrUseNonce)
	}
	return nil
}

// parseProof checks the header strictly and the signature with the
// embedded key, and decodes the claims.
func parseProof(compact string) (ed25519.PublicKey, proofClaims, error) {
	var c proofClaims
	parts := strings.Split(compact, ".")
	if len(compact) > maxProofBytes || strings.ContainsAny(compact, " \t\r\n") || len(parts) != 3 {
		return nil, c, refuse(ErrInvalidProof)
	}
	enc := base64.RawURLEncoding.Strict()
	head, err1 := enc.DecodeString(parts[0])
	payload, err2 := enc.DecodeString(parts[1])
	sig, err3 := enc.DecodeString(parts[2])
	var h struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		JWK struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		} `json:"jwk"`
	}
	if err1 != nil || err2 != nil || err3 != nil || json.Unmarshal(head, &h, json.RejectUnknownMembers(true)) != nil {
		return nil, c, refuse(ErrInvalidProof)
	}
	x, err := enc.DecodeString(h.JWK.X)
	if h.Alg != "EdDSA" || h.Typ != TypeProof || h.JWK.Kty != "OKP" || h.JWK.Crv != "Ed25519" || err != nil || len(x) != ed25519.PublicKeySize {
		return nil, c, refuse(ErrInvalidProof)
	}
	if !ed25519.Verify(x, []byte(parts[0]+"."+parts[1]), sig) || json.Unmarshal(payload, &c) != nil {
		return nil, c, refuse(ErrInvalidProof)
	}
	return x, c, nil
}

// sameHTU compares scheme and host without case and the path exactly; a
// query, fragment or user information never matches.
func sameHTU(claimed, want string) bool {
	a, err1 := url.Parse(claimed)
	b, err2 := url.Parse(want)
	if err1 != nil || err2 != nil {
		return false
	}
	for _, u := range []*url.URL{a, b} {
		if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Host == "" ||
			(!strings.EqualFold(u.Scheme, "https") && !strings.EqualFold(u.Scheme, "http")) {
			return false
		}
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host) && a.EscapedPath() == b.EscapedPath()
}

func printable(s string) bool {
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

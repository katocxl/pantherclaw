// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package pap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net/url"
	"strings"
	"time"
)

// ProofParams describe the request a workload signs a proof for (PAP/1 §4).
type ProofParams struct {
	// Method and URL are the request's; the URL's query and fragment are
	// left out of htu.
	Method string
	URL    string
	// Body is the exact request body.
	Body []byte
	// Token is the workload token sent in "Authorization: PAP"; empty for
	// a key-only proof (enrollment, token issuance).
	Token string
	// Nonce is the server's latest PAP-Nonce; empty before the first one.
	Nonce string
	// IssuedAt is the proof's iat (now when zero).
	IssuedAt time.Time
	// JTI is the proof's unique id; empty draws 128 random bits.
	JTI string
}

type proofClaims struct {
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	JTI   string `json:"jti"`
	ATH   string `json:"ath,omitempty"`
	BH    string `json:"bh"`
	Nonce string `json:"nonce,omitempty"`
}

// SignProof returns the PAP-Proof JWS for p: header {alg, jwk, typ} with
// the public key embedded, claims htm, htu, iat, jti, ath, bh and nonce.
func SignProof(priv ed25519.PrivateKey, p ProofParams) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("pap: the proof key must be an Ed25519 private key")
	}
	htu, err := HTU(p.URL)
	if err != nil {
		return "", err
	}
	if p.Method == "" {
		return "", errors.New("pap: the proof needs the request method")
	}
	jti := p.JTI
	if jti == "" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return "", err
		}
		jti = b64(id[:])
	}
	iat := p.IssuedAt
	if iat.IsZero() {
		iat = time.Now()
	}
	c := proofClaims{HTM: p.Method, HTU: htu, IAT: iat.Unix(), JTI: jti, BH: BodyHash(p.Body), Nonce: p.Nonce}
	if p.Token != "" {
		c.ATH = ATH(p.Token)
	}
	claims, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	header := `{"alg":"EdDSA","jwk":{"crv":"Ed25519","kty":"OKP","x":"` + b64(pub) + `"},"typ":"` + TypeProof + `"}`
	input := b64([]byte(header)) + "." + b64(claims)
	return input + "." + b64(ed25519.Sign(priv, []byte(input))), nil
}

// HTU returns the htu of a request URL: scheme, host and path, without
// query, fragment or user information.
func HTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return "", errors.New("pap: the request URL must be an absolute http(s) URL without user information")
	}
	return u.Scheme + "://" + u.Host + u.EscapedPath(), nil
}

// BodyHash returns bh: base64url(SHA-256(body)).
func BodyHash(body []byte) string {
	s := sha256.Sum256(body)
	return b64(s[:])
}

// ATH returns ath: base64url(SHA-256(token)).
func ATH(token string) string {
	s := sha256.Sum256([]byte(token))
	return b64(s[:])
}

// segment decodes one base64url segment of a compact JWS.
func segment(compact string, i int) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, errors.New("pap: not a compact JWS")
	}
	return base64.RawURLEncoding.Strict().DecodeString(parts[i])
}

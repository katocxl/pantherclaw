// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pap

import (
	"crypto/sha256"
	"crypto/subtle"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// DPoP proofs (RFC 9449) bind an MCP access token to its client's key (G0
// M30 D912, D913). They are checked by the same code as PAP/1 proofs: the
// same algorithms, the embedded public Ed25519 jwk only, and the same jti
// shape. A DPoP proof carries no body hash.
const (
	// DPoPType is the JWS typ of a DPoP proof.
	DPoPType = "dpop+jwt"
	// DPoPLeeway bounds a DPoP proof's iat on either side of now.
	DPoPLeeway = 60 * time.Second
	// DPoPReplayFor is how long a jti spent at the token endpoint is kept.
	DPoPReplayFor = 5 * time.Minute
)

// ProofAlgorithms are the JWS algorithms a PAP/1 or DPoP proof may use;
// metadata advertises them as dpop_signing_alg_values_supported (D914).
var ProofAlgorithms = []string{string(jose.EdDSA)}

// ValidJKT reports whether s has the shape of an RFC 7638 SHA-256
// thumbprint, as dpop_jkt carries it (RFC 9449 §10).
func ValidJKT(s string) bool { return jktPattern.MatchString(s) }

// DPoPRequest is what the verifier itself knows about the request a DPoP
// proof claims to cover. URL is the verifier's own: the token endpoint's
// configured URL, or the resource URL the access token's aud was checked
// against. Token is the access token the proof must be bound to (ath);
// empty at the token endpoint, where a proof carries no ath.
type DPoPRequest struct {
	Method string
	URL    string
	Token  string
}

// VerifyDPoP checks a DPoP proof statelessly (RFC 9449 §4.3): typ, alg, the
// signature with its public jwk, htm, htu, ath, iat within DPoPLeeway and
// the jti's shape. The nonce, when present, is returned unchecked: at a
// resource the caller requires it and passes the result to the replay
// store through the nonce check (Service.Consume); at the token endpoint
// the caller records the jti itself.
func VerifyDPoP(proof string, req DPoPRequest, now time.Time) (Checked, error) {
	key, c, err := parseProofOf(proof, DPoPType)
	if err != nil {
		return Checked{}, err
	}
	if c.HTM != req.Method || req.Method == "" {
		return Checked{}, fail(CodeInvalidProof, "htm")
	}
	if !sameHTU(c.HTU, req.URL) {
		return Checked{}, fail(CodeInvalidProof, "htu")
	}
	if req.Token != "" {
		sum := sha256.Sum256([]byte(req.Token))
		if subtle.ConstantTimeCompare([]byte(c.ATH), []byte(b64(sum[:]))) != 1 {
			return Checked{}, fail(CodeInvalidProof, "ath")
		}
	} else if c.ATH != "" {
		return Checked{}, fail(CodeInvalidProof, "ath without a token")
	}
	if c.BH != "" {
		return Checked{}, fail(CodeInvalidProof, "a DPoP proof carries no body hash")
	}
	iat := time.Unix(c.IAT, 0)
	if iat.After(now.Add(DPoPLeeway)) || iat.Before(now.Add(-DPoPLeeway)) {
		return Checked{}, fail(CodeInvalidProof, "iat")
	}
	if len(c.JTI) < 22 || len(c.JTI) > 128 || !printableASCII(c.JTI) {
		return Checked{}, fail(CodeInvalidProof, "jti")
	}
	if c.Nonce != "" && !ValidNonce(c.Nonce) {
		return Checked{}, fail(CodeUseNonce, "nonce malformed")
	}
	return Checked{key: key, jkt: jws.Thumbprint(key), jti: c.JTI, nonce: c.Nonce, iat: iat}, nil
}

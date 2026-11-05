// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package receiptsig adds PAP-1 §9.4's reserved sigs[] to receipts: an
// ML-DSA-65 co-signature by the deployment's receipts_pq key (G0 M35 D1042,
// HR-784). The compact JWS of a receipt is unchanged; sigs[] travels next
// to it:
//
//	[{"alg": "ML-DSA-65", "kid": "<receipts_pq kid>", "sig": "<base64url>"}]
//
// where sig is pure ML-DSA-65 (FIPS 204) with the context string
// "pantherclaw.receipt/v1" over the JWS signing input, the ASCII
// "<protected header>.<payload>" of the compact JWS. Decision, execution and
// effect receipts get it while evidence.mldsa_cosign is on (Enterprise; off
// in FIPS mode, HR-396). Federated receipts stay Ed25519 only.
package receiptsig

import (
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// Context is the FIPS 204 context string of receipt co-signatures.
const Context = "pantherclaw.receipt/v1"

// AlgMLDSA65 names the one algorithm sigs[] carries.
const AlgMLDSA65 = "ML-DSA-65"

// MaxSigs caps the entries of one sigs[].
const MaxSigs = 4

// ErrNoKey reports a co-signature asked for without an active receipts_pq
// key: the receipt is not signed at all (fail closed).
var ErrNoKey = errors.New("receiptsig: no active receipts_pq key")

// ErrInvalid reports a sigs[] that is malformed or does not verify.
var ErrInvalid = errors.New("receiptsig: invalid receipt co-signature")

// Sig is one entry of sigs[].
type Sig struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Sig string `json:"sig"` // base64url without padding
}

// SigningInput returns the JWS signing input of a compact JWS.
func SigningInput(compact string) ([]byte, error) {
	i := strings.LastIndexByte(compact, '.')
	if i <= 0 || strings.Count(compact, ".") != 2 {
		return nil, fmt.Errorf("%w: not a compact JWS", ErrInvalid)
	}
	return []byte(compact[:i]), nil
}

// Digest is the SHA-256 of a compact JWS: the receipt_sha256 its ledger
// entry carries, and the key its sigs[] is stored under.
func Digest(compact string) []byte {
	sum := sha256.Sum256([]byte(compact))
	return sum[:]
}

// Sign co-signs a compact JWS with an ML-DSA-65 key.
func Sign(compact, kid string, priv *mldsa.PrivateKey) (Sig, error) {
	in, err := SigningInput(compact)
	if err != nil {
		return Sig{}, err
	}
	if priv == nil || priv.PublicKey().Parameters() != mldsa.MLDSA65() {
		return Sig{}, errors.New("receiptsig: not an ML-DSA-65 key")
	}
	sig, err := priv.Sign(nil, in, &mldsa.Options{Context: Context})
	if err != nil {
		return Sig{}, fmt.Errorf("receiptsig: sign: %w", err)
	}
	return Sig{Alg: AlgMLDSA65, Kid: kid, Sig: base64.RawURLEncoding.EncodeToString(sig)}, nil
}

// Verify checks one entry of sigs[] over a compact JWS with pub.
func Verify(compact string, s Sig, pub *mldsa.PublicKey) error {
	if s.Alg != AlgMLDSA65 {
		return fmt.Errorf("%w: algorithm %q", ErrInvalid, s.Alg)
	}
	in, err := SigningInput(compact)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(s.Sig)
	if err != nil || len(sig) != mldsa.MLDSA65SignatureSize {
		return fmt.Errorf("%w: malformed signature", ErrInvalid)
	}
	if pub == nil || mldsa.Verify(pub, in, sig, &mldsa.Options{Context: Context}) != nil {
		return fmt.Errorf("%w: the ML-DSA-65 signature does not verify", ErrInvalid)
	}
	return nil
}

// Parse decodes a stored or carried sigs[].
func Parse(raw []byte) ([]Sig, error) {
	var out []Sig
	if err := json.Unmarshal(raw, &out, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if len(out) == 0 || len(out) > MaxSigs {
		return nil, fmt.Errorf("%w: 1..%d entries", ErrInvalid, MaxSigs)
	}
	for _, s := range out {
		if s.Kid == "" || len(s.Kid) > 128 || len(s.Sig) > 8192 {
			return nil, fmt.Errorf("%w: malformed entry", ErrInvalid)
		}
	}
	return out, nil
}

// JWSSigner signs receipts with the receipts key (jws.Signer).
type JWSSigner interface {
	Sign(typ string, payload []byte) (string, error)
}

// Signer signs receipts with the receipts key and co-signs them with the
// active receipts_pq key. Its CoSign is what the receipt writers look for.
type Signer struct {
	Next JWSSigner
	Keys *keys.Registry
}

// Sign implements the receipts signer: the compact JWS, unchanged.
func (s *Signer) Sign(typ string, payload []byte) (string, error) { return s.Next.Sign(typ, payload) }

// CoSign returns the encoded sigs[] of a compact JWS.
func (s *Signer) CoSign(compact string) ([]byte, error) {
	ks := s.Keys.AltKeys(keys.PurposeReceiptsPQ)
	if len(ks) == 0 || ks[0].State != keys.StateActive {
		return nil, ErrNoKey
	}
	priv, ok := ks[0].Private.Reveal().(*mldsa.PrivateKey)
	if !ok {
		return nil, ErrNoKey
	}
	sig, err := Sign(compact, ks[0].KID, priv)
	if err != nil {
		return nil, err
	}
	return json.Marshal([]Sig{sig})
}

// CoSigner is a receipts signer that also co-signs.
type CoSigner interface {
	CoSign(compact string) ([]byte, error)
}

// Of returns the sigs[] of compact when signer co-signs, and nil when it
// does not (evidence.mldsa_cosign off).
func Of(signer any, compact string) ([]byte, error) {
	c, ok := signer.(CoSigner)
	if !ok {
		return nil, nil
	}
	return c.CoSign(compact)
}

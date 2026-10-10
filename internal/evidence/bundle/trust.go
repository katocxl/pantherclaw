// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
)

// TrustFormat is the trust file format identifier.
const TrustFormat = "pantherclaw.trust/v1"

// MaxTrustBytes caps a trust file.
const MaxTrustBytes = 1 << 20

// ErrInvalidTrust reports a malformed trust file.
var ErrInvalidTrust = errors.New("bundle: invalid pantherclaw.trust/v1 trust file")

// Key purposes and algorithms of a trust file (G0 M7 design decision 17).
const (
	PurposeReceipts      = "receipts"
	PurposeCheckpoints   = "checkpoints"
	PurposeCheckpointsPQ = "checkpoints_pq"
	PurposeAnchors       = "anchors"
	PurposeEvidencePacks = "evidence_packs"

	AlgEdDSA   = "EdDSA"
	AlgES256   = "ES256"
	AlgMLDSA65 = "ML-DSA-65"
)

// purposeAlg pins each purpose to its one algorithm (HR-095).
var purposeAlg = map[string]string{
	PurposeReceipts: AlgEdDSA, PurposeCheckpoints: AlgEdDSA, PurposeEvidencePacks: AlgEdDSA,
	PurposeCheckpointsPQ: AlgMLDSA65, PurposeAnchors: AlgES256,
}

// Key states, as the deployment's key registry names them.
const (
	StateActive   = "ACTIVE"
	StateRetiring = "RETIRING"
	StateRevoked  = "REVOKED"
)

// Trust is a trust file: the evidence keys a user pinned from a deployment's
// evidence-keys.json (PAP-1 §11), and the deployment's log origin. `pclaw
// verify` trusts nothing else.
//
// A key's public_key is standard base64 of: the 32-byte RFC 8032 key
// (EdDSA), the PKIX DER SubjectPublicKeyInfo (ES256), or the 1,952-byte
// FIPS 204 encoding (ML-DSA-65).
type Trust struct {
	Format    string       `json:"format"`
	Issuer    string       `json:"issuer,omitzero"` // the deployment the keys came from
	LogOrigin string       `json:"log_origin"`
	Keys      []TrustedKey `json:"keys"`
}

// TrustedKey is one pinned key with its validity.
type TrustedKey struct {
	KID       string    `json:"kid"`
	Purpose   string    `json:"purpose"`
	Algorithm string    `json:"algorithm"`
	PublicKey []byte    `json:"public_key"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after,omitzero"`
	State     string    `json:"state"`

	ed    ed25519.PublicKey
	ec    *ecdsa.PublicKey
	mldsa *mldsa.PublicKey
}

// ValidAt reports whether the key may have signed at t: within its
// validity and not revoked.
func (k *TrustedKey) ValidAt(t time.Time) bool {
	return k.State != StateRevoked && !t.Before(k.NotBefore) && (k.NotAfter.IsZero() || !t.After(k.NotAfter))
}

// EvidenceKeysFormat is the format of a deployment's
// /.well-known/pantherclaw/evidence-keys.json (PAP-1 §11). The document has
// the trust file's members, so pinning it is a change of format alone.
const EvidenceKeysFormat = "pantherclaw.evidence-keys/v1"

// ParseTrust parses and checks a trust file: known purposes, each with its
// pinned algorithm, well-formed keys, unique kids and states.
func ParseTrust(b []byte) (*Trust, error) { return parseTrust(b, TrustFormat) }

// ParseEvidenceKeys parses and checks a deployment's evidence-keys.json like
// a trust file, and returns it as the trust file that pins those keys.
func ParseEvidenceKeys(b []byte) (*Trust, error) {
	t, err := parseTrust(b, EvidenceKeysFormat)
	if err != nil {
		return nil, err
	}
	t.Format = TrustFormat
	return t, nil
}

func parseTrust(b []byte, format string) (*Trust, error) {
	if len(b) > MaxTrustBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalidTrust, MaxTrustBytes)
	}
	var t Trust
	if err := json.Unmarshal(b, &t, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidTrust, err)
	}
	if t.Format != format || t.LogOrigin == "" || len(t.LogOrigin) > 256 || strings.ContainsAny(t.LogOrigin, " \n+") {
		return nil, fmt.Errorf("%w: format and a log origin are required", ErrInvalidTrust)
	}
	seen := map[string]bool{}
	for i := range t.Keys {
		k := &t.Keys[i]
		if k.KID == "" || len(k.KID) > 128 || seen[k.KID] {
			return nil, fmt.Errorf("%w: missing or repeated kid", ErrInvalidTrust)
		}
		seen[k.KID] = true
		if err := k.parse(); err != nil {
			return nil, fmt.Errorf("%w: key %s: %w", ErrInvalidTrust, k.KID, err)
		}
	}
	return &t, nil
}

func (k *TrustedKey) parse() error {
	if alg, ok := purposeAlg[k.Purpose]; !ok || alg != k.Algorithm {
		return fmt.Errorf("purpose %q with algorithm %q is not allowed", k.Purpose, k.Algorithm)
	}
	switch k.State {
	case StateActive, StateRetiring, StateRevoked:
	default:
		return fmt.Errorf("unknown state %q", k.State)
	}
	if k.NotBefore.IsZero() || (!k.NotAfter.IsZero() && k.NotAfter.Before(k.NotBefore)) {
		return errors.New("invalid validity")
	}
	switch k.Algorithm {
	case AlgEdDSA:
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return errors.New("an EdDSA key is 32 bytes")
		}
		k.ed = ed25519.PublicKey(k.PublicKey)
	case AlgES256:
		pub, err := anchor.ParseAnchorKey(k.PublicKey)
		if err != nil {
			return err
		}
		k.ec = pub
	case AlgMLDSA65:
		pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), k.PublicKey)
		if err != nil {
			return err
		}
		k.mldsa = pub
	}
	return nil
}

// keys returns the pinned keys of a purpose.
func (t *Trust) keys(purpose string) []*TrustedKey {
	var out []*TrustedKey
	for i := range t.Keys {
		if t.Keys[i].Purpose == purpose {
			out = append(out, &t.Keys[i])
		}
	}
	return out
}

// key returns the pinned key of a purpose with kid.
func (t *Trust) key(purpose, kid string) *TrustedKey {
	for _, k := range t.keys(purpose) {
		if k.KID == kid {
			return k
		}
	}
	return nil
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// AltKey is a signing key whose algorithm is not EdDSA (G0 M7 design
// decisions 6 and 17): the anchors key (ECDSA P-256) and the checkpoints_pq
// key (ML-DSA-65). Public is the key as it is stored and published: PKIX
// DER for ES256, the 1,952-byte FIPS 204 encoding for ML-DSA-65. Private is
// set only on the active key: an *ecdsa.PrivateKey or an *mldsa.PrivateKey.
type AltKey struct {
	KID     string
	Purpose Purpose
	State   State
	Public  []byte
	Private pclog.Secret[crypto.Signer]
}

// AltKIDFor derives the kid of an alternative-algorithm key:
// "<purpose>-<base64url(SHA-256(public key encoding)) prefix>".
func AltKIDFor(purpose Purpose, public []byte) string {
	sum := sha256.Sum256(public)
	return strings.ReplaceAll(string(purpose), "_", "-") + "-" + base64.RawURLEncoding.EncodeToString(sum[:])[:22]
}

func altPurpose(p Purpose) error {
	if !slices.Contains(AltPurposes(), p) {
		return fmt.Errorf("keys: %q is not an alternative-algorithm purpose", p)
	}
	return nil
}

// GenerateAltKey creates a new active key for an alternative-algorithm
// purpose. It also returns the private encoding to store wrapped: the
// 32-byte P-256 scalar, or the 32-byte ML-DSA-65 seed.
func GenerateAltKey(purpose Purpose) (AltKey, pclog.Secret[[]byte], error) {
	if err := altPurpose(purpose); err != nil {
		return AltKey{}, pclog.Secret[[]byte]{}, err
	}
	var signer crypto.Signer
	var private []byte
	switch purpose.Algorithm() {
	case AlgES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return AltKey{}, pclog.Secret[[]byte]{}, fmt.Errorf("keys: generate: %w", err)
		}
		if private, err = k.Bytes(); err != nil {
			return AltKey{}, pclog.Secret[[]byte]{}, fmt.Errorf("keys: generate: %w", err)
		}
		signer = k
	case AlgMLDSA65:
		k, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			return AltKey{}, pclog.Secret[[]byte]{}, fmt.Errorf("keys: generate: %w", err)
		}
		private, signer = k.Bytes(), k
	case AlgEdDSA:
		return AltKey{}, pclog.Secret[[]byte]{}, fmt.Errorf("keys: %q is an Ed25519 purpose", purpose)
	}
	public, err := publicEncoding(purpose.Algorithm(), signer)
	if err != nil {
		return AltKey{}, pclog.Secret[[]byte]{}, err
	}
	return AltKey{
		KID: AltKIDFor(purpose, public), Purpose: purpose, State: StateActive, Public: public,
		Private: pclog.NewSecret(signer),
	}, pclog.NewSecret(private), nil
}

// OpenAltKey rebuilds the active key kid of purpose from its stored private
// encoding, and checks it is the key of public.
func OpenAltKey(purpose Purpose, kid string, public, private []byte) (AltKey, error) {
	if err := altPurpose(purpose); err != nil {
		return AltKey{}, err
	}
	var signer crypto.Signer
	switch purpose.Algorithm() {
	case AlgES256:
		k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), private)
		if err != nil {
			return AltKey{}, fmt.Errorf("keys: %s: malformed private key", kid)
		}
		signer = k
	case AlgMLDSA65:
		k, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), private)
		if err != nil {
			return AltKey{}, fmt.Errorf("keys: %s: malformed private key", kid)
		}
		signer = k
	case AlgEdDSA:
		return AltKey{}, fmt.Errorf("keys: %q is an Ed25519 purpose", purpose)
	}
	derived, err := publicEncoding(purpose.Algorithm(), signer)
	if err != nil {
		return AltKey{}, err
	}
	if !bytes.Equal(derived, public) {
		return AltKey{}, fmt.Errorf("keys: %s: private key does not match its public key", kid)
	}
	return AltKey{KID: kid, Purpose: purpose, State: StateActive, Public: public, Private: pclog.NewSecret(signer)}, nil
}

func publicEncoding(alg Algorithm, s crypto.Signer) ([]byte, error) {
	switch k := s.(type) {
	case *ecdsa.PrivateKey:
		if alg != AlgES256 {
			break
		}
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("keys: encode public key: %w", err)
		}
		return der, nil
	case *mldsa.PrivateKey:
		if alg != AlgMLDSA65 {
			break
		}
		return k.PublicKey().Bytes(), nil
	}
	return nil, fmt.Errorf("keys: a %T is not an %s key", s, alg)
}

// checkAltPublic checks that public is a well-formed key of alg.
func checkAltPublic(alg Algorithm, public []byte) error {
	switch alg {
	case AlgES256:
		k, err := x509.ParsePKIXPublicKey(public)
		if ec, ok := k.(*ecdsa.PublicKey); err != nil || !ok || ec.Curve != elliptic.P256() {
			return errors.New("not a PKIX ECDSA P-256 public key")
		}
	case AlgMLDSA65:
		if _, err := mldsa.NewPublicKey(mldsa.MLDSA65(), public); err != nil {
			return errors.New("not an ML-DSA-65 public key")
		}
	case AlgEdDSA:
		return errors.New("EdDSA is not an alternative algorithm")
	default:
		return fmt.Errorf("algorithm %s is not an alternative algorithm", alg)
	}
	return nil
}

// PutAlt adds or replaces an alternative-algorithm key. At most one key per
// purpose may be Active, and an Active key must carry its private half.
func (r *Registry) PutAlt(k AltKey) error {
	if err := altPurpose(k.Purpose); err != nil {
		return err
	}
	if err := checkAltPublic(k.Purpose.Algorithm(), k.Public); err != nil || k.KID != AltKIDFor(k.Purpose, k.Public) {
		return fmt.Errorf("keys: kid %q does not match a well-formed public key of its purpose", k.KID)
	}
	switch k.State {
	case StateActive:
		priv := k.Private.Reveal()
		if priv == nil {
			return fmt.Errorf("keys: active key %q needs its private key", k.KID)
		}
		if pub, err := publicEncoding(k.Purpose.Algorithm(), priv); err != nil || !bytes.Equal(pub, k.Public) {
			return fmt.Errorf("keys: active key %q needs its matching private key", k.KID)
		}
	case StateRetiring, StateRevoked:
	default:
		return fmt.Errorf("keys: invalid state %q", k.State)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if k.State == StateActive {
		for kid, other := range r.alt {
			if kid != k.KID && other.Purpose == k.Purpose && other.State == StateActive {
				return fmt.Errorf("keys: purpose %q already has active key %q", k.Purpose, kid)
			}
		}
	}
	k.Public = bytes.Clone(k.Public)
	r.alt[k.KID] = k
	return nil
}

// AltKeys returns the non-revoked keys of an alternative-algorithm purpose,
// the active one first, then by kid.
func (r *Registry) AltKeys(purpose Purpose) []AltKey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []AltKey
	for _, k := range r.alt {
		if k.Purpose == purpose && k.State != StateRevoked {
			out = append(out, k)
		}
	}
	slices.SortFunc(out, func(a, b AltKey) int {
		if (a.State == StateActive) != (b.State == StateActive) {
			if a.State == StateActive {
				return -1
			}
			return 1
		}
		return strings.Compare(a.KID, b.KID)
	})
	return out
}

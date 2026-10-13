// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package cose converts a stored WebAuthn public key (a COSE key) to the
// form a customer-hosted gateway pins: a DER SubjectPublicKeyInfo (PKIX)
// with its COSE algorithm (G0 M6 slice 23, HR-038). Only the algorithms
// security keys may use are accepted (HR-153).
package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// COSE identifiers.
const (
	algES256  = -7
	algEdDSA  = -8
	algRS256  = -257
	curveP256 = 1
	curveEd   = 6
)

// ErrUnsupported refuses a key of another type, curve or algorithm.
var ErrUnsupported = errors.New("cose: unsupported public key")

// PKIX returns a COSE public key's algorithm and its DER
// SubjectPublicKeyInfo.
func PKIX(key []byte) (int, []byte, error) {
	parsed, err := webauthncose.ParsePublicKey(key)
	if err != nil {
		return 0, nil, errors.Join(ErrUnsupported, err)
	}
	var pub crypto.PublicKey
	var alg int64
	switch k := parsed.(type) {
	case webauthncose.EC2PublicKeyData:
		if k.Algorithm != algES256 || k.Curve != curveP256 || len(k.XCoord) != 32 || len(k.YCoord) != 32 {
			return 0, nil, ErrUnsupported
		}
		p, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, k.XCoord...), k.YCoord...))
		if err != nil {
			return 0, nil, errors.Join(ErrUnsupported, err)
		}
		pub, alg = p, k.Algorithm
	case webauthncose.OKPPublicKeyData:
		if k.Algorithm != algEdDSA || k.Curve != curveEd || len(k.XCoord) != ed25519.PublicKeySize {
			return 0, nil, ErrUnsupported
		}
		pub, alg = ed25519.PublicKey(k.XCoord), k.Algorithm
	case webauthncose.RSAPublicKeyData:
		e := new(big.Int).SetBytes(k.Exponent)
		if k.Algorithm != algRS256 || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return 0, nil, ErrUnsupported
		}
		pub, alg = &rsa.PublicKey{N: new(big.Int).SetBytes(k.Modulus), E: int(e.Int64())}, k.Algorithm
	default:
		return 0, nil, ErrUnsupported
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return 0, nil, errors.Join(ErrUnsupported, err)
	}
	return int(alg), der, nil
}

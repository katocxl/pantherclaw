// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package webauthntest is a software WebAuthn authenticator and client for
// tests: it answers PantherClaw's creation and request options the way a
// browser and a security key would (attestation "none"), and knobs make it
// misbehave (another origin or RP id, no user verification, a counter that
// does not move, changed backup flags, a weak RSA key).
package webauthntest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"math/big"
	"slices"
)

// Alg is a COSE algorithm the authenticator can use.
type Alg int

// Algorithms. RS1024 is RS256 with a 1,024-bit key, which must be refused.
const (
	ES256  Alg = -7
	EdDSA  Alg = -8
	RS256  Alg = -257
	RS1024 Alg = 1024
)

// Authenticator flags (WebAuthn §6.1).
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
)

// Authenticator holds one credential. Its exported fields are knobs.
type Authenticator struct {
	// Origin and RPID are what the client reports; they default to the
	// values given to New.
	Origin, RPID string
	// NoUV leaves the user-verified flag unset.
	NoUV bool
	// BackupEligible and BackupState are reported in every authenticator
	// data (a synced passkey has both).
	BackupEligible, BackupState bool
	// Counter is the next signature counter; it grows by one per assertion
	// unless ZeroCounter (synced passkeys report 0).
	Counter     uint32
	ZeroCounter bool

	alg        Alg
	key        crypto.Signer
	credID     []byte
	userHandle []byte
}

// New returns an authenticator for origin and RP id with a fresh key.
func New(origin, rpID string, alg Alg) (*Authenticator, error) {
	a := &Authenticator{Origin: origin, RPID: rpID, alg: alg, Counter: 1}
	var err error
	switch alg {
	case ES256:
		a.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case EdDSA:
		_, a.key, err = ed25519.GenerateKey(rand.Reader)
	case RS256:
		a.key, err = rsa.GenerateKey(rand.Reader, 2048)
	case RS1024:
		a.key, err = rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: a deliberately weak key the relying party must refuse
	default:
		return nil, errors.New("webauthntest: unknown algorithm")
	}
	if err != nil {
		return nil, err
	}
	a.credID = make([]byte, 32)
	if _, err := rand.Read(a.credID); err != nil {
		return nil, err
	}
	return a, nil
}

// CredentialID is the credential's id.
func (a *Authenticator) CredentialID() []byte { return slices.Clone(a.credID) }

// PublicKey is the credential's public key.
func (a *Authenticator) PublicKey() crypto.PublicKey { return a.key.Public() }

// COSEKey is the credential's public key as the relying party stores it.
func (a *Authenticator) COSEKey() ([]byte, error) { return a.coseKey() }

var b64 = base64.RawURLEncoding

// creationOptions is the part of PublicKeyCredentialCreationOptions used.
type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		PubKeyCredParams []struct {
			Alg int `json:"alg"`
		} `json:"pubKeyCredParams"`
	} `json:"publicKey"`
}

// requestOptions is the part of PublicKeyCredentialRequestOptions used.
type requestOptions struct {
	PublicKey struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

func (a *Authenticator) coseAlg() int {
	if a.alg == RS1024 {
		return int(RS256)
	}
	return int(a.alg)
}

// Register answers creation options with a new credential (attestation
// "none"), as navigator.credentials.create and PublicKeyCredential.toJSON
// would.
func (a *Authenticator) Register(options []byte) ([]byte, error) {
	var o creationOptions
	if err := json.Unmarshal(options, &o, json.RejectUnknownMembers(false)); err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(o.PublicKey.PubKeyCredParams, func(p struct {
		Alg int `json:"alg"`
	},
	) bool {
		return p.Alg == a.coseAlg()
	}) {
		return nil, errors.New("webauthntest: algorithm not offered")
	}
	uh, err := b64.DecodeString(o.PublicKey.User.ID)
	if err != nil {
		return nil, err
	}
	a.userHandle = uh
	cdj := a.clientData("webauthn.create", o.PublicKey.Challenge)
	pub, err := a.coseKey()
	if err != nil {
		return nil, err
	}
	auth := a.authData(flagAT, 0)
	auth = append(auth, make([]byte, 16)...)                          // AAGUID: zero (attestation "none")
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(a.credID))) //nolint:gosec // G115: the credential id is 32 bytes
	auth = append(auth, a.credID...)
	auth = append(auth, pub...)
	att := cborMap(cborText("fmt"), cborText("none"), cborText("attStmt"), cborMap(), cborText("authData"), cborBytes(auth))
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"authenticatorAttachment": "cross-platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(cdj), "attestationObject": b64.EncodeToString(att),
			"transports": []string{"usb"},
		},
	})
}

// Assert answers request options with an assertion, if the credential is
// allowed, as navigator.credentials.get would.
func (a *Authenticator) Assert(options []byte) ([]byte, error) {
	var o requestOptions
	if err := json.Unmarshal(options, &o, json.RejectUnknownMembers(false)); err != nil {
		return nil, err
	}
	id := b64.EncodeToString(a.credID)
	if !slices.ContainsFunc(o.PublicKey.AllowCredentials, func(c struct {
		ID string `json:"id"`
	},
	) bool {
		return c.ID == id
	}) {
		return nil, errors.New("webauthntest: credential not allowed")
	}
	cdj := a.clientData("webauthn.get", o.PublicKey.Challenge)
	counter := a.Counter
	if a.ZeroCounter {
		counter = 0
	} else {
		a.Counter++
	}
	auth := a.authData(0, counter)
	sum := sha256.Sum256(cdj)
	sig, err := a.sign(append(slices.Clone(auth), sum[:]...))
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": id, "rawId": id, "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(cdj), "authenticatorData": b64.EncodeToString(auth),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(a.userHandle),
		},
	})
}

func (a *Authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	return b
}

func (a *Authenticator) authData(extra byte, counter uint32) []byte {
	rp := sha256.Sum256([]byte(a.RPID))
	flags := flagUP | extra
	if !a.NoUV {
		flags |= flagUV
	}
	if a.BackupEligible {
		flags |= flagBE
	}
	if a.BackupState {
		flags |= flagBS
	}
	out := append(rp[:], flags)
	return binary.BigEndian.AppendUint32(out, counter)
}

func (a *Authenticator) coseKey() ([]byte, error) {
	switch k := a.key.(type) {
	case *ecdsa.PrivateKey:
		e, err := k.PublicKey.ECDH()
		if err != nil {
			return nil, err
		}
		p := e.Bytes() // 0x04 || X || Y
		return cborMap(cborInt(1), cborInt(2), cborInt(3), cborInt(-7), cborInt(-1), cborInt(1),
			cborInt(-2), cborBytes(p[1:33]), cborInt(-3), cborBytes(p[33:65])), nil
	case ed25519.PrivateKey:
		pub, _ := k.Public().(ed25519.PublicKey)
		return cborMap(cborInt(1), cborInt(1), cborInt(3), cborInt(-8), cborInt(-1), cborInt(6), cborInt(-2), cborBytes(pub)), nil
	case *rsa.PrivateKey:
		e := big.NewInt(int64(k.E)).Bytes()
		return cborMap(cborInt(1), cborInt(3), cborInt(3), cborInt(-257), cborInt(-1), cborBytes(k.N.Bytes()), cborInt(-2), cborBytes(e)), nil
	}
	return nil, errors.New("webauthntest: unknown key")
}

func (a *Authenticator) sign(data []byte) ([]byte, error) {
	switch k := a.key.(type) {
	case *ecdsa.PrivateKey:
		sum := sha256.Sum256(data)
		return ecdsa.SignASN1(rand.Reader, k, sum[:])
	case ed25519.PrivateKey:
		return ed25519.Sign(k, data), nil
	case *rsa.PrivateKey:
		sum := sha256.Sum256(data)
		return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	}
	return nil, errors.New("webauthntest: unknown key")
}

// Minimal CBOR encoding (RFC 8949) for the shapes WebAuthn needs: integers,
// byte and text strings, and maps.

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n <= 0xff:
		return []byte{major<<5 | 24, byte(n)}
	case n <= 0xffff:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	default:
		return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n)) //nolint:gosec // G115: test values are small
	}
}

func cborInt(v int64) []byte {
	if v >= 0 {
		return cborHead(0, uint64(v))
	}
	return cborHead(1, uint64(-1-v))
}

func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }

func cborText(s string) []byte { return append(cborHead(3, uint64(len(s))), s...) }

func cborMap(kv ...[]byte) []byte {
	out := cborHead(5, uint64(len(kv)/2))
	for _, x := range kv {
		out = append(out, x...)
	}
	return out
}

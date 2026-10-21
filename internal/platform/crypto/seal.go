// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package crypto

import (
	"crypto/fips140"
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"fmt"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// ErrSealedFormat reports a malformed sealed blob.
var ErrSealedFormat = errors.New("crypto: malformed sealed blob")

// ErrSealSuiteNotFIPS refuses an X-Wing key or blob in FIPS mode (G0 M13
// D35, HR-396): X25519 is not a FIPS 140-3 approved algorithm, so a FIPS
// install seals with MLKEM768-P256 only and starts fresh.
var ErrSealSuiteNotFIPS = pcerr.New(pcerr.FailedPrecondition, "SEAL_SUITE_NOT_FIPS",
	"the sealed credential or broker key uses X-Wing (MLKEM768-X25519), which a FIPS build does not use; "+
		"generate a new broker key and seal the credential again")

// SealSuite is the HPKE KEM of a seal key or a sealed blob, by its HPKE KEM
// identifier. The KDF (HKDF-SHA256) and the AEAD (AES-256-GCM) are the same
// for every suite (SB-3, PAP-1 §2).
type SealSuite uint16

// The seal suites.
const (
	// SuiteXWing is MLKEM768-X25519 (X-Wing), the default outside FIPS mode.
	SuiteXWing SealSuite = 0x647a
	// SuiteMLKEM768P256 is the FIPS 140-3 suite: ML-KEM-768 with P-256.
	SuiteMLKEM768P256 SealSuite = 0x0050
)

// String names the suite.
func (s SealSuite) String() string {
	switch s {
	case SuiteXWing:
		return "MLKEM768-X25519"
	case SuiteMLKEM768P256:
		return "MLKEM768-P256"
	}
	return fmt.Sprintf("unknown(0x%04x)", uint16(s))
}

// fipsMode reports FIPS 140-3 mode; tests replace it.
var fipsMode = fips140.Enabled

// DefaultSealSuite is the suite new seal keys use: MLKEM768-P256 in FIPS
// mode, X-Wing otherwise.
func DefaultSealSuite() SealSuite {
	if fipsMode() {
		return SuiteMLKEM768P256
	}
	return SuiteXWing
}

func (s SealSuite) kem() (hpke.KEM, error) {
	switch s {
	case SuiteXWing:
		if fipsMode() {
			return nil, ErrSealSuiteNotFIPS
		}
		return hpke.MLKEM768X25519(), nil
	case SuiteMLKEM768P256:
		return hpke.MLKEM768P256(), nil
	}
	return nil, ErrSealedFormat
}

func sealKDFAEAD() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.AES256GCM() }

// Blob versions: v1 is X-Wing with no suite field (blobs sealed before
// M13); v2 records the suite (D35).
const (
	sealedV1 byte = 0x01
	sealedV2 byte = 0x02
)

// Encoded sizes that tell the suites apart.
const (
	xwingPublicKeySize = 1216
	p256PublicKeySize  = 1249
	seedSize           = 32
)

// SealPrivateKey is a seal decapsulation key (a broker key, HR-060).
type SealPrivateKey struct {
	suite SealSuite
	k     hpke.PrivateKey
}

// SealPublicKey is a seal encapsulation key.
type SealPublicKey struct {
	suite SealSuite
	k     hpke.PublicKey
}

// GenerateSealKey returns a new key pair of the default suite.
func GenerateSealKey() (*SealPrivateKey, error) { return GenerateSealKeySuite(DefaultSealSuite()) }

// GenerateSealKeySuite returns a new key pair of suite s.
func GenerateSealKeySuite(s SealSuite) (*SealPrivateKey, error) {
	kem, err := s.kem()
	if err != nil {
		return nil, err
	}
	k, err := kem.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("crypto: generate seal key: %w", err)
	}
	return &SealPrivateKey{suite: s, k: k}, nil
}

// ParseSealPrivateKey deserializes a private key produced by Bytes: a bare
// 32-byte seed is X-Wing (keys generated before M13), and any other suite
// carries its 2-byte KEM identifier first.
func ParseSealPrivateKey(b []byte) (*SealPrivateKey, error) {
	s, seed := SuiteXWing, b
	if len(b) == 2+seedSize {
		s, seed = SealSuite(binary.BigEndian.Uint16(b)), b[2:]
		if s == SuiteXWing {
			return nil, errors.New("crypto: parse seal private key: X-Wing keys carry no suite prefix")
		}
	}
	if len(seed) != seedSize {
		return nil, errors.New("crypto: parse seal private key: wrong length")
	}
	kem, err := s.kem()
	if err != nil {
		return nil, err
	}
	k, err := kem.NewPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse seal private key: %w", err)
	}
	return &SealPrivateKey{suite: s, k: k}, nil
}

// ParseSealPublicKey deserializes a public key produced by Bytes; its
// length tells the suite.
func ParseSealPublicKey(b []byte) (*SealPublicKey, error) {
	var s SealSuite
	switch len(b) {
	case xwingPublicKeySize:
		s = SuiteXWing
	case p256PublicKeySize:
		s = SuiteMLKEM768P256
	default:
		return nil, errors.New("crypto: parse seal public key: not an X-Wing or MLKEM768-P256 key")
	}
	kem, err := s.kem()
	if err != nil {
		return nil, err
	}
	k, err := kem.NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse seal public key: %w", err)
	}
	return &SealPublicKey{suite: s, k: k}, nil
}

// Suite is the key's suite.
func (p *SealPrivateKey) Suite() SealSuite { return p.suite }

// Bytes serializes the private key. Treat the result as a secret.
func (p *SealPrivateKey) Bytes() ([]byte, error) {
	seed, err := p.k.Bytes()
	if err != nil || p.suite == SuiteXWing {
		return seed, err
	}
	out := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(seed)), uint16(p.suite))
	out = append(out, seed...)
	clear(seed)
	return out, nil
}

// PublicKey returns the matching public key.
func (p *SealPrivateKey) PublicKey() *SealPublicKey {
	return &SealPublicKey{suite: p.suite, k: p.k.PublicKey()}
}

// Suite is the key's suite.
func (p *SealPublicKey) Suite() SealSuite { return p.suite }

// Bytes serializes the public key.
func (p *SealPublicKey) Bytes() []byte { return p.k.Bytes() }

// Seal encrypts plaintext to pub. info binds the context (for credentials:
// org, connection, version and allowed hosts, HR-060) and aad is additional
// authenticated data. The result is version 2 (1) ‖ suite (2) ‖ len(enc) (2)
// ‖ enc ‖ ct. HPKE binds the suite into its key schedule as well.
func Seal(pub *SealPublicKey, info, aad, plaintext []byte) ([]byte, error) {
	if len(info) == 0 {
		return nil, fmt.Errorf("%w: info must bind a context", ErrInvalidContext)
	}
	if _, err := pub.suite.kem(); err != nil {
		return nil, err
	}
	kdf, aead := sealKDFAEAD()
	enc, s, err := hpke.NewSender(pub.k, kdf, aead, info)
	if err != nil {
		return nil, fmt.Errorf("crypto: hpke sender: %w", err)
	}
	ct, err := s.Seal(aad, plaintext)
	if err != nil {
		return nil, fmt.Errorf("crypto: hpke seal: %w", err)
	}
	out := make([]byte, 0, 5+len(enc)+len(ct))
	out = append(out, sealedV2)
	out = binary.BigEndian.AppendUint16(out, uint16(pub.suite))
	out = binary.BigEndian.AppendUint16(out, uint16(len(enc))) //nolint:gosec // G115: enc is at most 1153 bytes
	out = append(out, enc...)
	return append(out, ct...), nil
}

// SealedSuite reports the suite a sealed blob was sealed with.
func SealedSuite(sealed []byte) (SealSuite, error) {
	s, _, _, err := parseSealed(sealed)
	return s, err
}

func parseSealed(sealed []byte) (SealSuite, []byte, []byte, error) {
	var s SealSuite
	var rest []byte
	switch {
	case len(sealed) >= 3 && sealed[0] == sealedV1:
		s, rest = SuiteXWing, sealed[1:]
	case len(sealed) >= 5 && sealed[0] == sealedV2:
		s, rest = SealSuite(binary.BigEndian.Uint16(sealed[1:3])), sealed[3:]
		if s != SuiteXWing && s != SuiteMLKEM768P256 {
			return 0, nil, nil, ErrSealedFormat
		}
	default:
		return 0, nil, nil, ErrSealedFormat
	}
	n := int(binary.BigEndian.Uint16(rest[:2]))
	if len(rest) < 2+n {
		return 0, nil, nil, ErrSealedFormat
	}
	return s, rest[2 : 2+n], rest[2+n:], nil
}

// Open decrypts a Seal output (either blob version). In FIPS mode an X-Wing
// blob returns ErrSealSuiteNotFIPS; any mismatch in key, suite, info, aad or
// content returns ErrDecrypt.
func Open(priv *SealPrivateKey, info, aad, sealed []byte) ([]byte, error) {
	s, enc, ct, err := parseSealed(sealed)
	if err != nil {
		return nil, err
	}
	if _, err := s.kem(); err != nil {
		return nil, err
	}
	if s != priv.suite {
		return nil, ErrDecrypt
	}
	kdf, aead := sealKDFAEAD()
	r, err := hpke.NewRecipient(enc, priv.k, kdf, aead, info)
	if err != nil {
		return nil, ErrDecrypt
	}
	pt, err := r.Open(aad, ct)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

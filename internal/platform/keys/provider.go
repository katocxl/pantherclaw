// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package keys manages PantherClaw's key hierarchy (SB-3, ADR-0012):
// key-encryption keys (KEKs) behind the KeyProvider port, and signing keys
// per purpose in a Registry that publishes a JWKS document.
//
// KEKs never leave the provider. The file provider is for development and
// self-hosting; OpenBao Transit and cloud KMS providers implement the same
// port later (docs/UPGRADES.md).
package keys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/katocxl/pantherclaw/internal/platform/config"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
)

// KeyProvider wraps and unwraps key material with a KEK.
type KeyProvider interface {
	// CurrentKEK returns the id of the KEK that Wrap uses.
	CurrentKEK() string
	// Wrap encrypts plaintext under the current KEK, bound to aad.
	Wrap(ctx context.Context, plaintext, aad []byte) ([]byte, error)
	// Unwrap decrypts a Wrap output (any KEK the provider still holds).
	Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error)
}

// ErrUnwrap is returned for every unwrap failure.
var ErrUnwrap = errors.New("keys: unwrap failed")

const wrapV1 byte = 0x01

// FileProvider holds KEKs read from secret files. The first file is the
// current KEK; the others remain available for unwrapping during rotation.
type FileProvider struct {
	current string
	keks    map[string]*pccrypto.AEAD
}

var _ KeyProvider = (*FileProvider)(nil)

// NewFileProvider loads KEK files. Each file holds the standard base64
// encoding of 32 random bytes (see GenerateKEKFile).
func NewFileProvider(paths []string) (*FileProvider, error) {
	if len(paths) == 0 {
		return nil, errors.New("keys: at least one KEK file is required")
	}
	p := &FileProvider{keks: make(map[string]*pccrypto.AEAD, len(paths))}
	for i, path := range paths {
		s, err := config.ReadSecretFile(path)
		if err != nil {
			return nil, fmt.Errorf("keys: KEK: %w", err)
		}
		raw := make([]byte, base64.StdEncoding.DecodedLen(len(s.Reveal())))
		n, err := base64.StdEncoding.Strict().Decode(raw, bytes.TrimSpace(s.Reveal()))
		if err != nil || n != pccrypto.KeySize {
			return nil, fmt.Errorf("keys: KEK file %s must contain base64 of %d bytes", path, pccrypto.KeySize)
		}
		kek := raw[:n]
		id := kekID(kek)
		if _, dup := p.keks[id]; dup {
			return nil, fmt.Errorf("keys: KEK file %s duplicates another KEK", path)
		}
		a, err := pccrypto.NewAEAD(kek)
		if err != nil {
			return nil, err
		}
		p.keks[id] = a
		if i == 0 {
			p.current = id
		}
	}
	return p, nil
}

// kekID is a non-secret identifier: a prefix of SHA-256 over the key.
func kekID(kek []byte) string {
	sum := sha256.Sum256(append([]byte("pc-kek-id-v1|"), kek...))
	return "kek-" + hex.EncodeToString(sum[:8])
}

// CurrentKEK implements KeyProvider.
func (p *FileProvider) CurrentKEK() string { return p.current }

func wrapAAD(kid string, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, errors.New("keys: wrap requires non-empty associated data")
	}
	return pccrypto.NewAAD("pc-kek-wrap-v1").Str(kid).Bytes(aad).Build()
}

// Wrap implements KeyProvider. Format: version ‖ len(kid) ‖ kid ‖ AEAD output.
func (p *FileProvider) Wrap(_ context.Context, plaintext, aad []byte) ([]byte, error) {
	full, err := wrapAAD(p.current, aad)
	if err != nil {
		return nil, err
	}
	out := []byte{wrapV1, byte(len(p.current))} //nolint:gosec // G115: KEK ids are 20 bytes (kekID)
	out = append(out, p.current...)
	return append(out, p.keks[p.current].Seal(plaintext, full)...), nil
}

// Unwrap implements KeyProvider.
func (p *FileProvider) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	if len(wrapped) < 2 || wrapped[0] != wrapV1 || len(wrapped) < 2+int(wrapped[1]) {
		return nil, ErrUnwrap
	}
	kid := string(wrapped[2 : 2+int(wrapped[1])])
	a, ok := p.keks[kid]
	if !ok {
		return nil, ErrUnwrap
	}
	full, err := wrapAAD(kid, aad)
	if err != nil {
		return nil, err
	}
	pt, err := a.Open(wrapped[2+len(kid):], full)
	if err != nil {
		return nil, ErrUnwrap
	}
	return pt, nil
}

// GenerateKEKFile writes a new random KEK to path with mode 0600. It refuses
// to overwrite an existing file.
func GenerateKEKFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: operator-chosen output path
	if err != nil {
		return fmt.Errorf("keys: create KEK file: %w", err)
	}
	enc := base64.StdEncoding.EncodeToString(pccrypto.NewKey()) + "\n"
	if _, err := f.WriteString(enc); err != nil {
		_ = f.Close()
		return fmt.Errorf("keys: write KEK file: %w", err)
	}
	return f.Close()
}

// Holds reports whether the provider has the KEK with this unprefixed id.
func (p *FileProvider) Holds(kid string) bool {
	_, ok := p.keks[kid]
	return ok
}

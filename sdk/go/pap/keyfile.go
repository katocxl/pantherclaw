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
	"fmt"
	"os"
)

// KeyFile is a workload's identity on disk (PAP/1 §3.1): its Ed25519 key,
// which never leaves the workload, and, once enrolled, its identifier, the
// PantherClaw server it enrolled with and optionally a run. Keep it
// owner-only and never log it.
type KeyFile struct {
	// PrivateKey is the Ed25519 seed (32 bytes), base64url without padding.
	PrivateKey string `json:"private_key"`
	// Identifier is pc:org/<org>/agent/<agent>/inst/<instance>.
	Identifier string `json:"identifier,omitempty"`
	// Server is the PantherClaw server's base URL.
	Server string `json:"server,omitempty"`
	// RunID is a run started for the workload.
	RunID string `json:"run_id,omitempty"`
}

// ErrKeyFile reports a key file that cannot be used.
var ErrKeyFile = errors.New("pap: invalid workload key file")

// NewKeyFile returns a key file holding a fresh key.
func NewKeyFile() (KeyFile, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return KeyFile{}, err
	}
	return KeyFile{PrivateKey: base64.RawURLEncoding.EncodeToString(seed)}, nil
}

// ParseKeyFile parses a key file strictly: unknown or duplicate members, a
// seed that is not 32 bytes of base64url without padding, or anything but
// one JSON object is refused.
func ParseKeyFile(b []byte) (KeyFile, error) {
	var k KeyFile
	if err := json.Unmarshal(b, &k, json.RejectUnknownMembers(true)); err != nil {
		return KeyFile{}, fmt.Errorf("%w: %w", ErrKeyFile, err)
	}
	if _, err := k.Key(); err != nil {
		return KeyFile{}, err
	}
	return k, nil
}

// Key returns the private key.
func (k KeyFile) Key() (ed25519.PrivateKey, error) {
	seed, err := base64.RawURLEncoding.Strict().DecodeString(k.PrivateKey)
	if err != nil || len(seed) != ed25519.SeedSize || len(k.PrivateKey) != 43 {
		return nil, fmt.Errorf("%w: private_key must be a base64url Ed25519 seed", ErrKeyFile)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Marshal returns the file's bytes as PantherClaw writes them: members in
// declaration order, empty ones left out, no whitespace, a final newline.
func (k KeyFile) Marshal() ([]byte, error) {
	b, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint (jkt) of an Ed25519
// public key, base64url without padding.
func Thumbprint(pub ed25519.PublicKey) string {
	s := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + b64(pub) + `"}`))
	return b64(s[:])
}

// ReadKeyFile reads and parses a key file.
func ReadKeyFile(path string) (KeyFile, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the caller chooses the path
	if err != nil {
		return KeyFile{}, err
	}
	return ParseKeyFile(b)
}

// WriteKeyFile writes k to a new owner-only file. An existing file is
// never overwritten unless replace is set.
func WriteKeyFile(path string, k KeyFile, replace bool) error {
	if _, err := k.Key(); err != nil {
		return err
	}
	b, err := k.Marshal()
	if err != nil {
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if replace {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600) //nolint:gosec // G304: the caller chooses the path
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workloadclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
)

// KeyFile is a workload's identity on disk (PAP-1 §3.1): its Ed25519 key,
// which never leaves the workload, and, once enrolled, its PAP/1
// identifier. It is written 0600 and never logged.
type KeyFile struct {
	// PrivateKey is the base64url Ed25519 seed (32 bytes).
	PrivateKey string `json:"private_key"`
	// Identifier is pc:org/<org>/agent/<agent>/inst/<instance>.
	Identifier string `json:"identifier,omitzero"`
	// Server is the PantherClaw server the workload enrolled with.
	Server string `json:"server,omitzero"`
	// RunID is a run started for the workload (development seeds only).
	RunID string `json:"run_id,omitzero"`
}

// NewKeyFile returns a key file with a fresh key.
func NewKeyFile() (KeyFile, ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return KeyFile{}, nil, err
	}
	return KeyFile{PrivateKey: base64.RawURLEncoding.EncodeToString(key.Seed())}, key, nil
}

// Key returns the private key.
func (k KeyFile) Key() (ed25519.PrivateKey, error) {
	seed, err := base64.RawURLEncoding.DecodeString(k.PrivateKey)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("workload key file: private_key must be a base64url Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ReadKeyFile reads a key file.
func ReadKeyFile(path string) (KeyFile, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: operator-chosen path
	if err != nil {
		return KeyFile{}, fmt.Errorf("workload key file: %w", err)
	}
	var k KeyFile
	if err := json.Unmarshal(b, &k, json.RejectUnknownMembers(true)); err != nil {
		return KeyFile{}, fmt.Errorf("workload key file: %w", err)
	}
	if _, err := k.Key(); err != nil {
		return KeyFile{}, err
	}
	return k, nil
}

// WriteKeyFile writes k to a file only the person can read (0600, or on
// Windows an access list of its own), private from the moment it exists. An
// existing file is never overwritten unless replace is set; then the key is
// written to a new private file that replaces it, so nobody who could open
// the old one reads the new key.
func WriteKeyFile(path string, k KeyFile, replace bool) error {
	b, err := json.Marshal(k, json.Deterministic(true))
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if !replace {
		return writePrivate(path, b)
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := path + ".new-" + hex.EncodeToString(suffix[:])
	if err := writePrivate(tmp, b); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("workload key file: %w", err)
	}
	return nil
}

// writePrivate writes b to a new private file, removed again if writing
// fails.
func writePrivate(path string, b []byte) error {
	f, err := createPrivate(path)
	if err != nil {
		return fmt.Errorf("workload key file: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("workload key file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("workload key file: %w", err)
	}
	return nil
}

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
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
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

// String describes the key file without its private key, so printing or
// logging one never shows the seed.
func (k KeyFile) String() string {
	return fmt.Sprintf("pap.KeyFile{identifier: %q, server: %q, run_id: %q, private_key: [redacted]}", k.Identifier, k.Server, k.RunID)
}

// GoString is String, for %#v.
func (k KeyFile) GoString() string { return k.String() }

// keyFileJSON is a KeyFile without its methods: the file's own encoding.
type keyFileJSON KeyFile

// MarshalJSON encodes the key file without its private key, so a JSON
// dump of a configuration that holds one never shows the seed. Marshal
// and WriteKeyFile write the file itself.
func (k KeyFile) MarshalJSON() ([]byte, error) {
	r := keyFileJSON(k)
	r.PrivateKey = "[redacted]"
	return json.Marshal(r)
}

// LogValue is the key file for log/slog, without its private key.
func (k KeyFile) LogValue() slog.Value {
	return slog.GroupValue(slog.String("identifier", k.Identifier), slog.String("server", k.Server), slog.String("run_id", k.RunID))
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
	b, err := json.Marshal(keyFileJSON(k))
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

// ReadKeyFile reads and parses a key file. Outside Windows it refuses a
// file that its group or others may read or write, as ssh does.
func ReadKeyFile(path string) (KeyFile, error) {
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			return KeyFile{}, err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return KeyFile{}, fmt.Errorf("%w: %s is open to other users (mode %v); run chmod 600 on it", ErrKeyFile, path, info.Mode().Perm())
		}
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: the caller chooses the path
	if err != nil {
		return KeyFile{}, err
	}
	return ParseKeyFile(b)
}

// WriteKeyFile writes k to an owner-only file. It writes a temporary file
// in the same directory, syncs it and then links it to path, so a crash
// never leaves a partial key. An existing file is never overwritten unless
// replace is set; then it is replaced atomically, and the new file is
// owner-only whatever the old one's mode was. (On Windows, owner-only
// comes from the directory's access list, not from the mode.)
func WriteKeyFile(path string, k KeyFile, replace bool) (err error) {
	if _, err := k.Key(); err != nil {
		return err
	}
	b, err := k.Marshal()
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".pantherclaw-key-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if replace {
		return os.Rename(tmp, path)
	}
	// A link fails when path exists, so an existing key is never replaced.
	err = link(tmp, path)
	switch {
	case err == nil:
		_ = os.Remove(tmp)
		return nil
	case errors.Is(err, fs.ErrExist):
		return err
	}
	// The filesystem has no hard links (FAT, exFAT, some network or FUSE
	// mounts): claim the name with O_EXCL, then rename the key over it.
	claim, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the caller chooses the path
	if err != nil {
		return err
	}
	if err := claim.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(path) // the empty file this call claimed
		return err
	}
	return nil
}

// link is os.Link; tests replace it to stand for a filesystem without
// hard links.
var link = os.Link

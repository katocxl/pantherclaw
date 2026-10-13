// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package broker is the gateway's credential broker (G0 M6 design decision
// 8, HR-060, HR-061, HR-182). The gateway operator generates a broker key
// (X-Wing) once; its private half is stored wrapped with a key-encryption
// key file (AES-256-GCM, with the key's fingerprint as associated data).
// The gateway registers the public half over its mTLS identity at start.
// A sealed credential opens only inside one dispatch, with the binding the
// gateway rebuilds from its own view, and only for a request to one of the
// hosts it is bound to; the plaintext is dropped when the request ends.
package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// Errors. A credential that does not open fails its dispatch before any
// byte is sent (enforcement_failed).
var (
	ErrKeyFile    = errors.New("broker: the broker key file is missing, malformed or does not unwrap")
	ErrOpen       = errors.New("broker: the credential does not open for this gateway, connection and binding")
	ErrNotBound   = errors.New("broker: the request goes to a host the credential is not bound to")
	ErrNoBroker   = errors.New("broker: no broker key is configured")
	errWrongOwner = errors.New("broker: the credential is sealed to another broker key")
)

// keyFile is the on-disk broker key.
type keyFile struct {
	V           int    `json:"v"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   []byte `json:"public_key"`
	Wrapped     []byte `json:"wrapped_private_key"`
}

// Key is a loaded broker key.
type Key struct {
	priv        *pccrypto.SealPrivateKey
	public      []byte
	fingerprint string
}

// Fingerprint is "sha256:<hex>" of the public key, as the server and pclaw
// seal show it.
func Fingerprint(public []byte) string {
	sum := sha256.Sum256(public)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// PublicKey is the X-Wing public key to register.
func (k *Key) PublicKey() []byte { return k.public }

// Fingerprint is the key's fingerprint.
func (k *Key) Fingerprint() string { return k.fingerprint }

// Generate creates a broker key and writes it to path (mode 0600, never
// over an existing file), wrapped with the first of kekFiles. It returns
// the fingerprint for the operator to give whoever seals credentials.
func Generate(ctx context.Context, path string, kekFiles []string) (string, error) {
	kek, err := keys.NewFileProvider(kekFiles)
	if err != nil {
		return "", err
	}
	priv, err := pccrypto.GenerateSealKey()
	if err != nil {
		return "", err
	}
	raw, err := priv.Bytes()
	if err != nil {
		return "", err
	}
	defer clear(raw)
	public := priv.PublicKey().Bytes()
	fp := Fingerprint(public)
	wrapped, err := kek.Wrap(ctx, raw, []byte(fp))
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(keyFile{V: 1, Fingerprint: fp, PublicKey: public, Wrapped: wrapped})
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: operator-chosen key file
	if err != nil {
		return "", fmt.Errorf("broker: create the key file: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return "", err
	}
	return fp, f.Close()
}

// Load reads and unwraps a broker key file and checks that the private key
// matches its recorded public key and fingerprint.
func Load(ctx context.Context, path string, kekFiles []string) (*Key, error) {
	kek, err := keys.NewFileProvider(kekFiles)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: operator-chosen key file
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyFile, err)
	}
	var f keyFile
	if err := json.Unmarshal(b, &f, json.RejectUnknownMembers(true)); err != nil || f.V != 1 || f.Fingerprint != Fingerprint(f.PublicKey) {
		return nil, ErrKeyFile
	}
	raw, err := kek.Unwrap(ctx, f.Wrapped, []byte(f.Fingerprint))
	if err != nil {
		return nil, ErrKeyFile
	}
	defer clear(raw)
	priv, err := pccrypto.ParseSealPrivateKey(raw)
	if err != nil || Fingerprint(priv.PublicKey().Bytes()) != f.Fingerprint {
		return nil, ErrKeyFile
	}
	return &Key{priv: priv, public: f.PublicKey, fingerprint: f.Fingerprint}, nil
}

// Sealed is a sealed credential as the gateway's configuration carries it.
type Sealed struct {
	Version   int32
	BrokerKey string // the id the server gave the registered key
	Blob      []byte
	Header    string
	Scheme    string
	// Kind is the credential kind the seal bound (empty or static, or
	// github_app).
	Kind string
}

// Open opens a sealed credential with the binding rebuilt from the
// gateway's own view: the org from its certificate, the connection and its
// allowed hosts from its configuration, the broker key id the server gave
// this gateway's key. ownKey is that id. The caller drops the plaintext
// when its request ends (clear).
func (k *Key) Open(org, connection string, allowedHosts []string, ownKey string, s Sealed) ([]byte, error) {
	if k == nil {
		return nil, ErrNoBroker
	}
	if s.BrokerKey != ownKey || ownKey == "" {
		return nil, fmt.Errorf("%w: %w", ErrOpen, errWrongOwner)
	}
	b := domain.Binding{
		Org: org, Connection: connection, Version: s.Version, AllowedHosts: allowedHosts, BrokerKey: ownKey,
		Header: s.Header, Scheme: s.Scheme, Kind: s.Kind,
	}
	pt, err := pccrypto.Open(k.priv, b.Info(), domain.AAD, s.Blob)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

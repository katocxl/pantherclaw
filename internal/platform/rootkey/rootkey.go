// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package rootkey creates and stores the offline root signing keys
// (licence signing, package signing) used only by pclaw-admin (HR-063), and
// in the same format the org package-signing keys pclaw makes on a
// customer's machine (HR-162) and the development package key `dev seed`
// keeps in deploy/dev/secrets (HR-163).
//
// Private keys are written as PKCS#8 in a PEM block. With a passphrase the
// block is encrypted: PBKDF2-HMAC-SHA256 (600,000 iterations, 16-byte salt)
// derives an AES-256-GCM key, and the AAD binds purpose and kid. Files are
// created with mode 0600 and never overwritten. Keep them on two offline
// media; never copy them to CI or servers.
package rootkey

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// Purpose of a root key.
type Purpose string

// Root purposes.
const (
	PurposeLicence  Purpose = "licence"
	PurposePackages Purpose = "packages"
	// PurposeOrgPackages is an org's own package-signing key (HR-162),
	// created by pclaw on the customer's machine. It is not a PantherClaw
	// root: pclaw-admin never makes one.
	PurposeOrgPackages Purpose = "org-packages"
	// PurposeDevPackages is the development package key (HR-163), created
	// by `pantherclaw-server dev seed`. It is not a root either: only a
	// server whose listeners are all on loopback trusts it.
	PurposeDevPackages Purpose = "packages-dev"
	// PurposeHub is the offline root that signs the PantherClaw Hub index
	// (G0 M23 D101, HR-560). It is separate from the package root: a Hub
	// document never verifies as a package document, or the reverse.
	PurposeHub Purpose = "hub"
	// PurposeDevHub is the development Hub key. It is not a root: only a
	// server or a source on loopback trusts it (D101).
	PurposeDevHub Purpose = "hub-dev"
)

// Valid reports whether p is a known purpose.
func (p Purpose) Valid() bool {
	return slices.Contains([]Purpose{PurposeLicence, PurposePackages, PurposeOrgPackages, PurposeDevPackages, PurposeHub, PurposeDevHub}, p)
}

// Root reports whether p is one of PantherClaw's offline roots.
func (p Purpose) Root() bool { return p == PurposeLicence || p == PurposePackages || p == PurposeHub }

const (
	plainType     = "PANTHERCLAW ROOT PRIVATE KEY"
	encryptedType = "PANTHERCLAW ENCRYPTED ROOT PRIVATE KEY"
	iterations    = 600_000
	// MinPassphrase is the minimum passphrase length.
	MinPassphrase = 16
)

// ErrKeyFile reports an unreadable or invalid key file.
var ErrKeyFile = errors.New("rootkey: invalid key file")

// KID derives the kid of a root public key: "<purpose>-root-<thumbprint>",
// or "org-packages-<thumbprint>" for an org package-signing key (equal to
// trust.OrgKID), "packages-dev-<thumbprint>" for the development package
// key (equal to trust.DevKID) and "hub-dev-<thumbprint>" for the development
// Hub key.
func KID(p Purpose, pub ed25519.PublicKey) string {
	if p == PurposeOrgPackages || p == PurposeDevPackages || p == PurposeDevHub {
		return string(p) + "-" + jws.Thumbprint(pub)[:22]
	}
	return string(p) + "-root-" + jws.Thumbprint(pub)[:22]
}

// Generate creates a new root key pair.
func Generate(p Purpose) (ed25519.PrivateKey, string, error) {
	if !p.Valid() {
		return nil, "", fmt.Errorf("rootkey: unknown purpose %q", p)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	return priv, KID(p, pub), nil
}

func aad(p Purpose, kid string) []byte { return []byte("pc-root-key-v1|" + string(p) + "|" + kid) }

func deriveKey(passphrase, salt []byte, iter int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(passphrase), salt, iter, 32)
}

// Encode returns the PEM file content for priv. An empty passphrase writes
// an unencrypted key (only acceptable on encrypted offline media).
func Encode(p Purpose, priv ed25519.PrivateKey, passphrase []byte) ([]byte, error) {
	if !p.Valid() {
		return nil, fmt.Errorf("rootkey: unknown purpose %q", p)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	kid := KID(p, pub)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{"Purpose": string(p), "Kid": kid}
	if len(passphrase) == 0 {
		return pem.EncodeToMemory(&pem.Block{Type: plainType, Headers: headers, Bytes: der}), nil
	}
	if len(passphrase) < MinPassphrase {
		return nil, fmt.Errorf("rootkey: passphrase must be at least %d characters", MinPassphrase)
	}
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key, err := deriveKey(passphrase, salt, iterations)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	headers["Kdf"] = "pbkdf2-sha256"
	headers["Iterations"] = strconv.Itoa(iterations)
	headers["Salt"] = base64.StdEncoding.EncodeToString(salt)
	return pem.EncodeToMemory(&pem.Block{Type: encryptedType, Headers: headers, Bytes: gcm.Seal(nil, nil, der, aad(p, kid))}), nil //nolint:gosec // G407: random-nonce GCM requires a nil nonce
}

// Decode parses a key file produced by Encode.
func Decode(b, passphrase []byte) (Purpose, ed25519.PrivateKey, error) {
	block, rest := pem.Decode(b)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return "", nil, fmt.Errorf("%w: not a single PEM block", ErrKeyFile)
	}
	p := Purpose(block.Headers["Purpose"])
	kid := block.Headers["Kid"]
	if !p.Valid() || kid == "" {
		return "", nil, fmt.Errorf("%w: missing purpose or kid", ErrKeyFile)
	}
	der := block.Bytes
	switch block.Type {
	case plainType:
	case encryptedType:
		if len(passphrase) == 0 {
			return "", nil, fmt.Errorf("%w: key is encrypted; a passphrase is required", ErrKeyFile)
		}
		iter, err := strconv.Atoi(block.Headers["Iterations"])
		if err != nil || iter < iterations || block.Headers["Kdf"] != "pbkdf2-sha256" {
			return "", nil, fmt.Errorf("%w: unsupported key derivation", ErrKeyFile)
		}
		salt, err := base64.StdEncoding.DecodeString(block.Headers["Salt"])
		if err != nil || len(salt) != 16 {
			return "", nil, fmt.Errorf("%w: bad salt", ErrKeyFile)
		}
		key, err := deriveKey(passphrase, salt, iter)
		if err != nil {
			return "", nil, err
		}
		gcm, err := newGCM(key)
		if err != nil {
			return "", nil, err
		}
		der, err = gcm.Open(nil, nil, block.Bytes, aad(p, kid))
		if err != nil {
			return "", nil, fmt.Errorf("%w: wrong passphrase or modified file", ErrKeyFile)
		}
	default:
		return "", nil, fmt.Errorf("%w: unexpected PEM type %q", ErrKeyFile, block.Type)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrKeyFile, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return "", nil, fmt.Errorf("%w: not an Ed25519 key", ErrKeyFile)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	if KID(p, pub) != kid {
		return "", nil, fmt.Errorf("%w: kid header does not match the key", ErrKeyFile)
	}
	return p, priv, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// WriteNew writes data to path with mode 0600, refusing to overwrite.
func WriteNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: operator-chosen output path
	if err != nil {
		return fmt.Errorf("rootkey: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("rootkey: %w", err)
	}
	return f.Close()
}

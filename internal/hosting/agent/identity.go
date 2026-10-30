// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package agent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateways/ca"
)

// identityFile holds the host agent's key, certificate and pinned CA.
const identityFile = "host-identity.json"

// Errors of the host identity.
var (
	ErrNoIdentity = errors.New("hosting agent: no host identity saved")
	ErrIdentity   = errors.New("hosting agent: invalid host identity")
	ErrPin        = errors.New("hosting agent: the CA certificate does not match the pin")
)

// Identity is the host agent's mTLS identity: a host certificate (one
// host, purpose "hosting", no org, HR-500) from the pinned CA.
type Identity struct {
	Host     ca.HostIdentity
	key      ed25519.PrivateKey
	certDER  []byte
	caDER    []byte
	leaf     *x509.Certificate
	caCert   *x509.Certificate
	CASHA256 string
}

type stored struct {
	V           int    `json:"v"`
	CASHA256    string `json:"ca_sha256"`
	Key         string `json:"key"`
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
}

// Pin is the "sha256:<hex>" pin of a DER certificate.
func Pin(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// NewIdentity checks that certDER is a host certificate for key that
// chains to caDER, which must match pin.
func NewIdentity(key ed25519.PrivateKey, certDER, caDER []byte, pin string) (*Identity, error) {
	if Pin(caDER) != pin {
		return nil, ErrPin
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil || !caCert.IsCA {
		return nil, fmt.Errorf("%w: CA certificate", ErrIdentity)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("%w: certificate: %w", ErrIdentity, err)
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return nil, fmt.Errorf("%w: the certificate is not for this key", ErrIdentity)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: pool, CurrentTime: leaf.NotBefore.Add(time.Minute), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("%w: the certificate does not chain to the pinned CA: %w", ErrIdentity, err)
	}
	h, err := ca.ParseHostIdentity(leaf)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIdentity, err)
	}
	return &Identity{Host: h, key: key, certDER: certDER, caDER: caDER, leaf: leaf, caCert: caCert, CASHA256: pin}, nil
}

// TLSCertificate is the client certificate for the mTLS client.
func (i *Identity) TLSCertificate() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{i.certDER}, PrivateKey: i.key, Leaf: i.leaf}
}

// Roots trusts only the internal CA.
func (i *Identity) Roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(i.caCert)
	return p
}

// NotAfter is when the certificate expires.
func (i *Identity) NotAfter() time.Time { return i.leaf.NotAfter }

// NotBefore is when the certificate starts.
func (i *Identity) NotBefore() time.Time { return i.leaf.NotBefore }

// Load reads the identity from dir and checks it against pin.
func Load(dir, pin string) (*Identity, error) {
	b, err := os.ReadFile(filepath.Join(dir, identityFile)) //nolint:gosec // G304: operator-chosen identity directory
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoIdentity
	} else if err != nil {
		return nil, err
	}
	var s stored
	if err := json.Unmarshal(b, &s, json.RejectUnknownMembers(true)); err != nil || s.V != 1 {
		return nil, fmt.Errorf("%w: %s", ErrIdentity, identityFile)
	}
	if pin != "" && pin != s.CASHA256 {
		return nil, ErrPin
	}
	seed, err1 := base64.RawURLEncoding.DecodeString(s.Key)
	cert, err2 := base64.StdEncoding.DecodeString(s.Certificate)
	caDER, err3 := base64.StdEncoding.DecodeString(s.CA)
	if err1 != nil || err2 != nil || err3 != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: %s", ErrIdentity, identityFile)
	}
	return NewIdentity(ed25519.NewKeyFromSeed(seed), cert, caDER, s.CASHA256)
}

// Save writes the identity to dir (0700) as a 0600 file, atomically.
func (i *Identity) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(stored{
		V: 1, CASHA256: i.CASHA256, Key: base64.RawURLEncoding.EncodeToString(i.key.Seed()),
		Certificate: base64.StdEncoding.EncodeToString(i.certDER), CA: base64.StdEncoding.EncodeToString(i.caDER),
	})
	if err != nil {
		return err
	}
	return writeAtomic(dir, identityFile, b, 0o600)
}

// writeAtomic writes name in dir through a temporary file and a rename.
func writeAtomic(dir, name string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(dir, name+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package proof

import (
	"cmp"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// FileFormat names version 1 of the approver keys file.
const FileFormat = "pantherclaw.approver-keys/v1"

// COSE algorithms a security key may use (HR-153).
const (
	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

// Bounds of the approver keys file.
const (
	maxFileBytes = 4 << 20
	maxKeys      = 10000
	minRSABits   = 2048
)

// File is the approver keys file a customer-hosted gateway pins
// (approvals.approver_keys_file): the org's people's security keys, as a
// person exported and reviewed them. It is written with `pclaw
// approver-keys export` (or `dev seed`) and only read by the gateway.
//
//	{
//	  "format": "pantherclaw.approver-keys/v1",
//	  "org": "<org id>",
//	  "rp_id": "<WebAuthn relying party id>",
//	  "exported_at": "<RFC 3339>",
//	  "keys": [{"user": "<user id>", "label": "<email (name)>", "key_name": "<name>",
//	            "credential_id": "<base64url>", "algorithm": -7,
//	            "public_key": "<base64 DER SubjectPublicKeyInfo>",
//	            "fingerprint": "sha256:<hex of the DER>"}]
//	}
//
// The label and key name are for review only; the gateway trusts the user
// id, credential id, algorithm and public key, and checks that each
// fingerprint matches its key.
type File struct {
	Format     string    `json:"format"`
	Org        string    `json:"org"`
	RPID       string    `json:"rp_id"`
	ExportedAt time.Time `json:"exported_at"`
	Keys       []FileKey `json:"keys"`
}

// FileKey is one pinned security key.
type FileKey struct {
	User         string `json:"user"`
	Label        string `json:"label"`
	KeyName      string `json:"key_name"`
	CredentialID string `json:"credential_id"`
	Algorithm    int    `json:"algorithm"`
	PublicKey    string `json:"public_key"`
	Fingerprint  string `json:"fingerprint"`
}

// NewFileKey encodes one key for the file and computes its fingerprint.
func NewFileKey(user, label, keyName string, credentialID []byte, algorithm int, pkix []byte) FileKey {
	return FileKey{
		User: user, Label: label, KeyName: keyName, CredentialID: B64(credentialID), Algorithm: algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(pkix), Fingerprint: Fingerprint(pkix),
	}
}

// Fingerprint is "sha256:" and the hex SHA-256 of a DER public key: what a
// person compares when reviewing the file.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Keys are the parsed, checked keys of a file.
type Keys struct {
	Org          string
	RPID         string
	byCredential map[string]*Key
}

// Len is how many keys are pinned.
func (k *Keys) Len() int { return len(k.byCredential) }

// Key is one pinned key.
type Key struct {
	User       string
	credential string
	pub        crypto.PublicKey
}

var rpPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// ParseFile parses and checks an approver keys file. Unknown members, an
// unknown format, a key whose algorithm and public key disagree, a weak
// RSA key, a fingerprint that does not match its key, and a credential id
// listed twice are refused.
func ParseFile(b []byte) (*Keys, error) {
	if len(b) > maxFileBytes {
		return nil, errors.New("approver keys: file too large")
	}
	var f File
	if err := json.Unmarshal(b, &f, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("approver keys: %w", err)
	}
	if f.Format != FileFormat {
		return nil, fmt.Errorf("approver keys: format %q, want %q", f.Format, FileFormat)
	}
	if _, err := ids.Parse[ids.Org](f.Org); err != nil {
		return nil, errors.New("approver keys: org is not an org id")
	}
	if !rpPattern.MatchString(f.RPID) {
		return nil, errors.New("approver keys: rp_id is not a domain name")
	}
	if len(f.Keys) > maxKeys {
		return nil, fmt.Errorf("approver keys: more than %d keys", maxKeys)
	}
	out := &Keys{Org: f.Org, RPID: f.RPID, byCredential: map[string]*Key{}}
	for i, fk := range f.Keys {
		k, err := parseKey(fk)
		if err != nil {
			return nil, fmt.Errorf("approver keys: key %d: %w", i, err)
		}
		if _, dup := out.byCredential[k.credential]; dup {
			return nil, fmt.Errorf("approver keys: key %d: credential id listed twice", i)
		}
		out.byCredential[k.credential] = k
	}
	return out, nil
}

func parseKey(fk FileKey) (*Key, error) {
	if _, err := ids.ParseUUID(fk.User); err != nil {
		return nil, errors.New("user is not an id")
	}
	cred, err := base64.RawURLEncoding.Strict().DecodeString(fk.CredentialID)
	if err != nil || len(cred) < 16 || len(cred) > 1023 {
		return nil, errors.New("credential_id is not 16 to 1023 base64url bytes")
	}
	der, err := base64.StdEncoding.Strict().DecodeString(fk.PublicKey)
	if err != nil || len(der) == 0 || len(der) > 2048 {
		return nil, errors.New("public_key is not base64 DER")
	}
	if fk.Fingerprint != Fingerprint(der) {
		return nil, errors.New("fingerprint does not match public_key")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("public_key: %w", err)
	}
	if err := algorithmFits(fk.Algorithm, pub); err != nil {
		return nil, err
	}
	return &Key{User: fk.User, credential: string(cred), pub: pub}, nil
}

// algorithmFits checks that a COSE algorithm and a public key agree.
func algorithmFits(alg int, pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if alg == AlgES256 && k.Curve == elliptic.P256() {
			return nil
		}
	case ed25519.PublicKey:
		if alg == AlgEdDSA {
			return nil
		}
	case *rsa.PublicKey:
		if alg == AlgRS256 && k.N.BitLen() >= minRSABits {
			return nil
		}
	}
	return fmt.Errorf("algorithm %d does not fit the public key (ES256 P-256, EdDSA Ed25519, RS256 of 2048 bits or more)", alg)
}

// Marshal encodes a file as reviewable JSON: indented, keys in the order
// given.
func (f File) Marshal() ([]byte, error) {
	if f.Keys == nil {
		f.Keys = []FileKey{}
	}
	b, err := json.Marshal(f, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	return indent(b)
}

// Pinned is the approver keys file a gateway verifies approvals against.
// It reads the file when first needed and again whenever its size or
// modification time changes, so an operator installs a reviewed export
// without restarting the gateway. Without a path, or while the file does
// not load, every approval is refused (fail closed).
type Pinned struct {
	path, org string

	mu    sync.Mutex
	keys  *Keys
	err   error
	size  int64
	mtime time.Time
	read  bool
}

// NewPinned pins the file at path for the gateway of org.
func NewPinned(path, org string) *Pinned { return &Pinned{path: path, org: org} }

// Verify verifies a permit's approval with the current file (see
// Keys.Verify).
func (p *Pinned) Verify(a *Approval, w Want) error {
	k, err := p.Keys()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNoKeys, err)
	}
	return k.Verify(a, w)
}

// Keys returns the file's keys, reading it again when it changed.
func (p *Pinned) Keys() (*Keys, error) {
	if p == nil || p.path == "" {
		return nil, errors.New("approvals.approver_keys_file is not set")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st, err := os.Stat(p.path)
	if err != nil {
		p.keys, p.err, p.read = nil, err, false
		return nil, err
	}
	if p.read && st.Size() == p.size && st.ModTime().Equal(p.mtime) {
		return p.keys, p.err
	}
	p.size, p.mtime, p.read = st.Size(), st.ModTime(), true
	p.keys, p.err = load(p.path, p.org)
	return p.keys, p.err
}

func load(path, org string) (*Keys, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the operator's configured file
	if err != nil {
		return nil, err
	}
	k, err := ParseFile(b)
	if err != nil {
		return nil, err
	}
	if k.Org != org {
		return nil, fmt.Errorf("approver keys: the file is for org %s, the gateway serves %s", k.Org, org)
	}
	return k, nil
}

// Sorted returns a file's keys ordered by label, key name and fingerprint,
// for printing.
func Sorted(keys []FileKey) []FileKey {
	out := slices.Clone(keys)
	slices.SortFunc(out, func(a, b FileKey) int {
		return cmp.Or(cmp.Compare(a.Label, b.Label), cmp.Compare(a.KeyName, b.KeyName), cmp.Compare(a.Fingerprint, b.Fingerprint))
	})
	return out
}

func indent(b []byte) ([]byte, error) {
	v := jsontext.Value(b)
	if err := v.Indent(jsontext.WithIndent("  ")); err != nil {
		return nil, err
	}
	return append([]byte(v), '\n'), nil
}

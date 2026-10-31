// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// Hub trust (G0 M23 D101, HR-560). The index is signed by the offline Hub
// root, which is separate from the package root: its typ header is its own,
// and its kid starts with RootKIDPrefix, so a Hub document never verifies as
// a package document, or the reverse. The development Hub key's kid starts
// with DevKIDPrefix: ParseRoots never accepts it, and only a server or a
// source on loopback adds it to the roots it verifies with.
const (
	// JOSEType is the JWS typ of the index.
	JOSEType = "pc-hub-index+jws"
	// RootKIDPrefix starts every Hub root kid.
	RootKIDPrefix = "hub-root-"
	// DevKIDPrefix starts the kid of a development Hub key.
	DevKIDPrefix = "hub-dev-"
)

// The verification errors: each maps to one stable code (D105).
var (
	// ErrSignature: the index does not verify, or is not a Hub index.
	ErrSignature = errors.New("hub: signature")
	// ErrExpired: the index is past its expiry.
	ErrExpired = errors.New("hub: expired")
	// ErrRollback: a lower index version, or the same version with another
	// digest.
	ErrRollback = errors.New("hub: rollback")
	// ErrDigest: an item is not what the index lists.
	ErrDigest = errors.New("hub: digest")
	// ErrNoRoot: nothing is trusted to sign an index.
	ErrNoRoot = errors.New("hub: no root")
)

// Roots are trusted Hub keys by kid.
type Roots map[string]ed25519.PublicKey

// RootKID derives the kid of a Hub root public key; it equals
// rootkey.KID(rootkey.PurposeHub, pub).
func RootKID(pub ed25519.PublicKey) string { return RootKIDPrefix + jws.Thumbprint(pub)[:22] }

// DevKID derives the kid of a development Hub public key; it equals
// rootkey.KID(rootkey.PurposeDevHub, pub).
func DevKID(pub ed25519.PublicKey) string { return DevKIDPrefix + jws.Thumbprint(pub)[:22] }

// IsDevKID reports whether kid names a development Hub key.
func IsDevKID(kid string) bool { return strings.HasPrefix(kid, DevKIDPrefix) }

func parseKeys(b []byte, kidOf func(ed25519.PublicKey) string) (Roots, error) {
	var doc struct {
		Keys []jws.JWK `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("hub: roots: %w", err)
	}
	roots := Roots{}
	for _, k := range doc.Keys {
		pub, err := k.Key()
		if err != nil {
			return nil, fmt.Errorf("hub: roots: %w", err)
		}
		if k.Kid != kidOf(pub) {
			return nil, fmt.Errorf("hub: roots: kid %q is not %s", k.Kid, kidOf(pub))
		}
		roots[k.Kid] = pub
	}
	return roots, nil
}

// ParseRoots parses a JWKS of Hub root keys whose kids are derived from the
// keys themselves.
func ParseRoots(b []byte) (Roots, error) { return parseKeys(b, RootKID) }

// ParseDevKey parses the public JWKS of a development Hub key: exactly one
// key, whose kid is the one derived from it.
func ParseDevKey(b []byte) (Roots, error) {
	roots, err := parseKeys(b, DevKID)
	if err != nil {
		return nil, err
	}
	if len(roots) != 1 {
		return nil, errors.New("hub: development key: want exactly one key")
	}
	return roots, nil
}

// Sign produces index.jws. It runs offline, in pclaw-admin, with the Hub root
// or the development Hub key.
func Sign(x Index, signer *jws.Signer) (string, error) {
	if kid, pub := signer.KeyID(), signer.Public(); kid != RootKID(pub) && kid != DevKID(pub) {
		return "", fmt.Errorf("hub: signing key %q is not a Hub root or the development Hub key", kid)
	}
	x.Spec = IndexSpec
	if _, err := x.Validate(); err != nil {
		return "", fmt.Errorf("hub: %w", err)
	}
	payload, err := json.Marshal(x, json.Deterministic(true))
	if err != nil {
		return "", fmt.Errorf("hub: %w", err)
	}
	return signer.Sign(JOSEType, payload)
}

// Verified is an index whose signature, shape and expiry checked out, with
// the hex SHA-256 of its payload (to detect equivocation).
type Verified struct {
	Index
	Expiry time.Time
	Digest string
	KID    string
}

// Verify checks index.jws against roots and its expiry at now.
func Verify(doc string, roots Roots, now time.Time) (Verified, error) {
	if len(roots) == 0 {
		return Verified{}, fmt.Errorf("%w: no Hub root keys are embedded in this build", ErrNoRoot)
	}
	v, err := jws.NewVerifier(JOSEType, roots)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	payload, kid, err := v.WithMaxBytes(MaxIndexBytes).Verify(strings.TrimSpace(doc))
	if err != nil {
		return Verified{}, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	var x Index
	if err := json.Unmarshal(payload, &x, json.RejectUnknownMembers(true)); err != nil {
		return Verified{}, fmt.Errorf("%w: payload: %w", ErrSignature, err)
	}
	exp, err := x.Validate()
	if err != nil {
		return Verified{}, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	if !now.Before(exp) {
		return Verified{}, fmt.Errorf("%w: index version %d expired at %s", ErrExpired, x.Version, x.ExpiresAt)
	}
	sum := sha256.Sum256(payload)
	return Verified{Index: x, Expiry: exp, Digest: hex.EncodeToString(sum[:]), KID: kid}, nil
}

// State is the last index accepted.
type State struct {
	Version uint64
	Digest  string
}

// CheckAdvance refuses an index older than the last accepted version, or
// another index under the same version (HR-562). A nil last means none was
// accepted before.
func CheckAdvance(last *State, next Verified) error {
	switch {
	case last == nil:
		return nil
	case next.Version < last.Version:
		return fmt.Errorf("%w: index version %d is older than the accepted %d", ErrRollback, next.Version, last.Version)
	case next.Version == last.Version && next.Digest != last.Digest:
		return fmt.Errorf("%w: a different index under version %d", ErrRollback, next.Version)
	}
	return nil
}

// Digest is the hex SHA-256 of raw, an item file's name without its .json.
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Match finds raw among the index's entries by its exact bytes and decodes
// it. Bytes are matched against the signed digest before they are parsed, so
// only signed bytes reach the decoder.
func (v Verified) Match(raw []byte) (Entry, Item, error) {
	sum := sha256.Sum256(raw)
	i := slices.IndexFunc(v.Items, func(e Entry) bool {
		want, err := hex.DecodeString(e.SHA256)
		return err == nil && int64(len(raw)) == e.Size && subtle.ConstantTimeCompare(sum[:], want) == 1
	})
	if i < 0 {
		return Entry{}, Item{}, fmt.Errorf("%w: the item matches no entry of index version %d", ErrDigest, v.Version)
	}
	e := v.Items[i]
	it, err := DecodeItem(raw)
	if err != nil {
		return Entry{}, Item{}, err
	}
	if it.Name != e.Name || it.Version != e.Version || it.Kind != e.Kind {
		return Entry{}, Item{}, fmt.Errorf("%w: the item declares %s@%s (%s), signed as %s@%s (%s)",
			ErrDigest, it.Name, it.Version, it.Kind, e.Name, e.Version, e.Kind)
	}
	return e, it, nil
}

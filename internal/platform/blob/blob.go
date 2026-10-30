// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package blob is the port for large immutable content (G0 M18 S18e, D157,
// D172): pack contents, policy bundles and captures that live in bytea
// columns today. A blob is addressed by its org, its kind and the SHA-256
// of its content, so a stored blob can't be changed in place and a reader
// can check what it got.
//
// Only the port and an in-memory adapter for tests (blobtest) exist. The
// real adapter comes with the first caller that moves off its bytea
// column; until then nothing uses this package and no behavior changes.
package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// MaxSize bounds one blob, as the largest bytea column today (packs).
const MaxSize = 64 << 20

// Errors.
var (
	ErrNotFound = errors.New("blob: not found")
	ErrInvalid  = errors.New("blob: invalid reference")
	ErrTooLarge = errors.New("blob: content too large")
)

var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// Ref names a blob.
type Ref struct {
	Org  ids.OrgID
	Kind string // for example "pack_content"
	// SHA256 is the hex SHA-256 of the content.
	SHA256 string
}

// RefFor returns the reference of content of kind in org.
func RefFor(org ids.OrgID, kind string, content []byte) Ref {
	sum := sha256.Sum256(content)
	return Ref{Org: org, Kind: kind, SHA256: hex.EncodeToString(sum[:])}
}

// Validate checks a reference's shape.
func (r Ref) Validate() error {
	if r.Org.IsZero() || !kindPattern.MatchString(r.Kind) || len(r.SHA256) != 64 {
		return ErrInvalid
	}
	if _, err := hex.DecodeString(r.SHA256); err != nil {
		return ErrInvalid
	}
	return nil
}

// Matches reports whether content is the blob r names.
func (r Ref) Matches(content []byte) bool {
	return RefFor(r.Org, r.Kind, content).SHA256 == r.SHA256
}

// Store keeps blobs per org. Every implementation scopes each call to the
// reference's org, as the tenant tables are (RLS).
type Store interface {
	// Put stores content and returns its reference; storing the same
	// content again is not an error.
	Put(ctx context.Context, org ids.OrgID, kind string, content []byte) (Ref, error)
	// Get returns the content of r, or ErrNotFound. The content matches
	// r.SHA256.
	Get(ctx context.Context, r Ref) ([]byte, error)
	// Delete removes r; deleting a missing blob is not an error.
	Delete(ctx context.Context, r Ref) error
}

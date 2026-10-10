// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"

	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Where sealed recordings are stored: the DEK purpose and the column the
// AAD binds with the org and transaction/evaluation (HR-062).
const (
	Purpose = "evaluation_inputs"
	table   = "evaluation_inputs"
	column  = "inputs"
)

// Size limits (design decision 11): a compressed recording above
// MaxCompressed is stored truncated, and a recording that opens to more than
// maxPlain is refused.
const (
	MaxCompressed = 32 << 10
	maxPlain      = 4 << 20
)

// Errors of Open.
var (
	// ErrTruncated reports inputs stored truncated: only their digest.
	ErrTruncated = errors.New("recording: the inputs were stored truncated")
	// ErrUnreadable reports inputs that do not open: another org, row or
	// key, tampering, or a corrupt recording.
	ErrUnreadable = errors.New("recording: the inputs cannot be opened")
)

// Sealed is a recording as its evaluation_inputs row holds it.
type Sealed struct {
	Format   int
	Pipeline int
	// Inputs is the sealed, compressed recording; nil when Truncated.
	Inputs []byte
	// Digest is the SHA-256 of the encoded recording.
	Digest    [sha256.Size]byte
	Truncated bool
}

// Sealer seals and opens recordings with the org's evaluation_inputs key.
type Sealer struct {
	env *pccrypto.Envelope
}

// NewSealer returns a Sealer over env.
func NewSealer(env *pccrypto.Envelope) *Sealer { return &Sealer{env: env} }

func field(org ids.OrgID, txn ids.UUID, evaluation int) pccrypto.FieldContext {
	return pccrypto.FieldContext{Org: org, Table: table, Column: column, RowID: txn.String() + "/" + strconv.Itoa(evaluation)}
}

// Seal encodes, compresses and seals r for the row of (txn, evaluation).
// Beyond MaxCompressed only the digest is kept, marked truncated.
func (s *Sealer) Seal(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int, r *Recording) (*Sealed, error) {
	plain, err := Encode(r)
	if err != nil {
		return nil, fmt.Errorf("recording: encode: %w", err)
	}
	out := &Sealed{Format: r.Format, Pipeline: r.Pipeline, Digest: sha256.Sum256(plain)}
	z, err := compress(plain)
	if err != nil {
		return nil, err
	}
	if len(z) > MaxCompressed {
		out.Truncated = true
		return out, nil
	}
	if out.Inputs, err = s.env.Encrypt(ctx, field(org, txn, evaluation), Purpose, z); err != nil {
		return nil, fmt.Errorf("recording: seal: %w", err)
	}
	return out, nil
}

// Open opens the row of (txn, evaluation): ErrFormat for a format this code
// does not read, ErrTruncated, or ErrUnreadable.
func (s *Sealer) Open(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int, row Sealed) (*Recording, error) {
	switch {
	case row.Format != FormatVersion:
		return nil, fmt.Errorf("%w: %d", ErrFormat, row.Format)
	case row.Truncated || row.Inputs == nil:
		return nil, ErrTruncated
	}
	z, err := s.env.Decrypt(ctx, field(org, txn, evaluation), Purpose, row.Inputs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	return Unpack(z, row)
}

// Unpack decompresses and decodes an opened recording and checks it against
// its row's digest and versions.
func Unpack(z []byte, row Sealed) (*Recording, error) {
	plain, err := decompress(z)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	if sum := sha256.Sum256(plain); subtle.ConstantTimeCompare(sum[:], row.Digest[:]) != 1 {
		return nil, fmt.Errorf("%w: the digest differs", ErrUnreadable)
	}
	r, err := Decode(plain)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	if r.Pipeline != row.Pipeline {
		return nil, fmt.Errorf("%w: the pipeline version differs from its row", ErrUnreadable)
	}
	return r, nil
}

// One flate writer is about a megabyte of state: reuse them.
var writers = sync.Pool{New: func() any {
	w, _ := flate.NewWriter(nil, flate.BestSpeed) // the level is valid
	return w
}}

func compress(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, _ := writers.Get().(*flate.Writer)
	defer writers.Put(w)
	w.Reset(&buf)
	if _, err := w.Write(b); err != nil {
		return nil, fmt.Errorf("recording: compress: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("recording: compress: %w", err)
	}
	return buf.Bytes(), nil
}

func decompress(z []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(z))
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, maxPlain+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxPlain {
		return nil, fmt.Errorf("more than %d bytes", maxPlain)
	}
	return b, nil
}

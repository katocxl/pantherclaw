// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the pure rules of the evidence ledger (ADR-0009,
// PAP-1 §9.4): entry validation, canonical encoding and hash chaining. It
// performs no I/O.
//
// Each chained entry is hashed as
//
//	entry_hash = SHA-256(prev_hash ‖ JCS(entry))
//
// where JCS is RFC 8785 canonical JSON of
//
//	{"v":1,"seq":N,"org":…,"id":…,"kind":…,"actor":{"type":…,"id":…},"ts":…,"body":{…}}
//
// and prev_hash of the first entry is 32 zero bytes. Binding seq and org into
// the hashed form makes reordering and cross-org splicing detectable.
package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// MaxBodyBytes caps the canonical body of one entry.
const MaxBodyBytes = 64 << 10

// HashSize is the size of entry hashes.
const HashSize = sha256.Size

// GenesisHash is prev_hash of the first entry of every org chain.
var GenesisHash = make([]byte, HashSize)

var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`)

// ErrInvalidEntry reports an entry that violates the ledger rules.
var ErrInvalidEntry = errors.New("evidence: invalid ledger entry")

// Actor identifies who caused an entry.
type Actor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Entry is one ledger record as stored.
type Entry struct {
	Org        ids.OrgID
	ID         ids.UUID
	Kind       string
	Actor      Actor
	OccurredAt time.Time
	Body       []byte // canonical JSON object
}

// Validate checks the entry fields (constraints mirror the table checks).
func (e Entry) Validate() error {
	switch {
	case e.Org.IsZero():
		return fmt.Errorf("%w: missing org", ErrInvalidEntry)
	case e.ID.IsZero():
		return fmt.Errorf("%w: missing id", ErrInvalidEntry)
	case len(e.Kind) > 128 || !kindPattern.MatchString(e.Kind):
		return fmt.Errorf("%w: kind %q must be a dotted lowercase name", ErrInvalidEntry, truncate(e.Kind))
	case e.Actor.Type == "" || len(e.Actor.Type) > 32 || e.Actor.ID == "" || len(e.Actor.ID) > 256:
		return fmt.Errorf("%w: actor type (1..32) and id (1..256) are required", ErrInvalidEntry)
	}
	return checkBody(e.Body)
}

func checkBody(b []byte) error {
	if len(b) < 2 || len(b) > MaxBodyBytes || b[0] != '{' {
		return fmt.Errorf("%w: body must be a JSON object of at most %d bytes", ErrInvalidEntry, MaxBodyBytes)
	}
	v := jsontext.Value(bytes.Clone(b))
	if err := v.Canonicalize(); err != nil || !bytes.Equal(v, b) {
		return fmt.Errorf("%w: body is not canonical JSON (RFC 8785)", ErrInvalidEntry)
	}
	return nil
}

// CanonicalBody encodes v as an RFC 8785 canonical JSON object. Values are
// marshaled with encoding/json/v2; duplicate names and invalid UTF-8 are
// rejected.
func CanonicalBody(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEntry, err)
	}
	val := jsontext.Value(b)
	if err := val.Canonicalize(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEntry, err)
	}
	if err := checkBody(val); err != nil {
		return nil, err
	}
	return val, nil
}

// Timestamp renders t as stored by PostgreSQL (microsecond precision, UTC).
func Timestamp(t time.Time) string {
	return t.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z")
}

// Canonical returns the bytes that are hashed for e at position seq.
func (e Entry) Canonical(seq int64) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	if seq < 1 {
		return nil, fmt.Errorf("%w: seq must be positive", ErrInvalidEntry)
	}
	doc := struct {
		V     int            `json:"v"`
		Seq   int64          `json:"seq"`
		Org   string         `json:"org"`
		ID    string         `json:"id"`
		Kind  string         `json:"kind"`
		Actor Actor          `json:"actor"`
		TS    string         `json:"ts"`
		Body  jsontext.Value `json:"body"`
	}{1, seq, e.Org.String(), e.ID.String(), e.Kind, e.Actor, Timestamp(e.OccurredAt), jsontext.Value(e.Body)}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEntry, err)
	}
	v := jsontext.Value(b)
	if err := v.Canonicalize(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEntry, err)
	}
	return v, nil
}

// LinkHash computes SHA-256(prev ‖ canonical).
func LinkHash(prev, canonical []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(canonical)
	return h.Sum(nil)
}

// Link is a chained position.
type Link struct {
	Seq       int64
	EntryID   ids.UUID
	PrevHash  []byte
	EntryHash []byte
}

// Next links e after a head (seq, hash).
func Next(headSeq int64, headHash []byte, e Entry) (Link, error) {
	if len(headHash) != HashSize {
		return Link{}, fmt.Errorf("%w: head hash must be %d bytes", ErrInvalidEntry, HashSize)
	}
	c, err := e.Canonical(headSeq + 1)
	if err != nil {
		return Link{}, err
	}
	return Link{Seq: headSeq + 1, EntryID: e.ID, PrevHash: bytes.Clone(headHash), EntryHash: LinkHash(headHash, c)}, nil
}

// ErrChainBroken reports a chain that fails verification.
var ErrChainBroken = errors.New("evidence: ledger chain broken")

// ChainError is an ErrChainBroken at one position of the chain.
type ChainError struct {
	Seq int64 // the first position that failed
	err error
}

func (e *ChainError) Error() string { return e.err.Error() }

// Unwrap returns the error, which wraps ErrChainBroken.
func (e *ChainError) Unwrap() error { return e.err }

func broken(seq int64, format string, args ...any) error {
	return &ChainError{Seq: seq, err: fmt.Errorf("%w: "+format, append([]any{ErrChainBroken}, args...)...)}
}

// Verifier checks a chain incrementally, in seq order.
type Verifier struct {
	seq  int64
	head []byte
}

// NewVerifier starts verification at the genesis of a chain.
func NewVerifier() *Verifier { return &Verifier{head: bytes.Clone(GenesisHash)} }

// NewVerifierAt starts verification after the position seq whose
// entry_hash is head (a checkpointed position).
func NewVerifierAt(seq int64, head []byte) (*Verifier, error) {
	if seq < 0 || len(head) != HashSize || (seq == 0 && !bytes.Equal(head, GenesisHash)) {
		return nil, fmt.Errorf("%w: invalid starting position", ErrInvalidEntry)
	}
	return &Verifier{seq: seq, head: bytes.Clone(head)}, nil
}

func (v *Verifier) position(l Link, id ids.UUID) error {
	switch {
	case l.Seq != v.seq+1:
		return broken(v.seq+1, "expected seq %d, found %d", v.seq+1, l.Seq)
	case l.EntryID != id:
		return broken(l.Seq, "seq %d links entry %s but carries %s", l.Seq, l.EntryID, id)
	case !bytes.Equal(l.PrevHash, v.head):
		return broken(l.Seq, "seq %d prev_hash does not match the previous entry", l.Seq)
	case len(l.EntryHash) != HashSize:
		return broken(l.Seq, "seq %d entry hash is not %d bytes", l.Seq, HashSize)
	}
	return nil
}

// Add verifies the next (link, entry) pair.
func (v *Verifier) Add(l Link, e Entry) error {
	if err := v.position(l, e.ID); err != nil {
		return err
	}
	c, err := e.Canonical(l.Seq)
	if err != nil {
		return broken(l.Seq, "seq %d: %w", l.Seq, err)
	}
	if !bytes.Equal(LinkHash(v.head, c), l.EntryHash) {
		return broken(l.Seq, "seq %d entry hash mismatch (entry or link altered)", l.Seq)
	}
	v.seq, v.head = l.Seq, bytes.Clone(l.EntryHash)
	return nil
}

// AddRemoved accepts the next link of an entry whose body retention
// removed (decision 4): its position and prev_hash are checked, and its
// stored entry_hash, which can no longer be recomputed, continues the chain.
func (v *Verifier) AddRemoved(l Link) error {
	if err := v.position(l, l.EntryID); err != nil {
		return err
	}
	v.seq, v.head = l.Seq, bytes.Clone(l.EntryHash)
	return nil
}

// Head returns the verified head (seq, hash).
func (v *Verifier) Head() (int64, []byte) { return v.seq, bytes.Clone(v.head) }

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

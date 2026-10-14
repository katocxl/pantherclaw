// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package bundle defines the pantherclaw.bundle/v1 verify bundle and the
// pantherclaw.trust/v1 trust file, and verifies a bundle offline against the
// keys a user pinned (G0 M7 design decision 13, HR-196, PAP-1 §9.4). It
// performs no I/O: `pclaw verify` reads the files and never contacts any
// service.
//
// A bundle holds the evidence of one org: receipts (compact JWS), ledger
// entries in their chained form (seq, prev_hash, entry_hash, and the body
// unless retention removed it), the org's signed checkpoints with
// inclusion proofs of the entries and consistency proofs between the
// checkpoints, optionally a checkpoint saved earlier (a witness), and
// optionally the anchor that commits to one of the checkpoints: the org's
// blinded leaf and nonce, the anchor's leaves, the signed statement, the
// Rekor v2 entry and the RFC 3161 timestamp response.
package bundle

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
)

// Format is the bundle format identifier.
const Format = "pantherclaw.bundle/v1"

// Limits of a bundle.
const (
	MaxBundleBytes  = 64 << 20
	MaxEntries      = 100_000
	MaxReceipts     = 100_000
	MaxCheckpoints  = 1_000
	MaxProofs       = 2 * MaxEntries
	maxProofHashes  = 64
	maxReceiptBytes = 64 << 10
	maxNoteBytes    = 64 << 10
)

// ErrInvalidBundle reports a bundle that is not a well-formed
// pantherclaw.bundle/v1 document.
var ErrInvalidBundle = errors.New("bundle: invalid pantherclaw.bundle/v1")

// Bundle is a verify bundle. Byte strings are standard base64.
type Bundle struct {
	Format      string        `json:"format"`
	Org         string        `json:"org"`
	Origin      string        `json:"origin"` // the checkpoints' origin, <log origin>/org/<org>
	Receipts    []string      `json:"receipts,omitzero"`
	Entries     []Entry       `json:"entries,omitzero"`
	Checkpoints []string      `json:"checkpoints,omitzero"` // signed checkpoint notes
	Inclusion   []Inclusion   `json:"inclusion,omitzero"`
	Consistency []Consistency `json:"consistency,omitzero"`
	Previous    string        `json:"previous,omitzero"` // a checkpoint saved earlier
	Anchor      *Anchor       `json:"anchor,omitzero"`
	// ProbeReports are the signed probe reports the bundle's sandbox.closure
	// entries name (HR-227).
	ProbeReports []ProbeReport `json:"probe_reports,omitzero"`
}

// Entry is a ledger entry in its chained form. Body is absent when
// retention removed it; Removed then says when and under which policy.
type Entry struct {
	Seq       int64          `json:"seq"`
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	Actor     domain.Actor   `json:"actor"`
	TS        string         `json:"ts"`
	Body      jsontext.Value `json:"body,omitzero"`
	Removed   *Removal       `json:"body_removed,omitzero"`
	PrevHash  []byte         `json:"prev_hash"`
	EntryHash []byte         `json:"entry_hash"`
}

// Removal is the tombstone of a body removed by retention.
type Removal struct {
	At     string `json:"at"`     // RFC 3339
	Policy string `json:"policy"` // the retention policy revision
}

// Inclusion proves an entry's entry_hash at leaf seq−1 of the checkpoint
// of tree size Size.
type Inclusion struct {
	Seq   int64    `json:"seq"`
	Size  uint64   `json:"size"`
	Proof [][]byte `json:"proof"`
}

// Consistency proves the checkpoint of size To extends the one of size
// From.
type Consistency struct {
	From  uint64   `json:"from"`
	To    uint64   `json:"to"`
	Proof [][]byte `json:"proof"`
}

// Anchor is the anchor that commits to the bundle's checkpoint of size
// Checkpoint (PAP-1 §9.4).
type Anchor struct {
	Checkpoint uint64         `json:"checkpoint"`
	Nonce      []byte         `json:"nonce"`
	Leaves     [][]byte       `json:"leaves"`    // the global tree's leaves, in order
	Statement  []byte         `json:"statement"` // the canonical anchor statement
	Signature  []byte         `json:"signature"` // ECDSA P-256 by the anchors key
	RekorEntry jsontext.Value `json:"rekor_entry,omitzero"`
	Timestamp  []byte         `json:"timestamp,omitzero"` // DER TimeStampResp over the signature
}

// Decode parses a bundle strictly: unknown or duplicate members, invalid
// UTF-8 and documents beyond the limits are rejected.
func Decode(b []byte) (*Bundle, error) {
	if len(b) > MaxBundleBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalidBundle, MaxBundleBytes)
	}
	var out Bundle
	if err := json.Unmarshal(b, &out, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidBundle, err)
	}
	if err := out.check(); err != nil {
		return nil, err
	}
	return &out, nil
}

// Encode returns the bundle as canonical JSON (RFC 8785).
func Encode(b *Bundle) ([]byte, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidBundle, err)
	}
	v := jsontext.Value(raw)
	if err := v.Canonicalize(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidBundle, err)
	}
	return v, nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidBundle, fmt.Sprintf(format, args...))
}

func (b *Bundle) check() error {
	switch {
	case b.Format != Format:
		return invalid("format %q", truncate(b.Format))
	case b.Org == "" || len(b.Org) > 64 || b.Origin == "" || len(b.Origin) > 512:
		return invalid("org and origin are required")
	case len(b.Entries) > MaxEntries || len(b.Receipts) > MaxReceipts || len(b.Checkpoints) > MaxCheckpoints:
		return invalid("too many entries, receipts or checkpoints")
	case len(b.Inclusion) > MaxProofs || len(b.Consistency) > MaxProofs:
		return invalid("too many proofs")
	}
	if len(b.ProbeReports) > maxProbeReports {
		return invalid("too many probe reports")
	}
	for _, p := range b.ProbeReports {
		if p.Run == "" || len(p.Run) > 64 || len(p.Report) == 0 || len(p.Report) > maxReceiptBytes {
			return invalid("a probe report is empty or larger than %d bytes", maxReceiptBytes)
		}
	}
	for _, r := range b.Receipts {
		if len(r) == 0 || len(r) > maxReceiptBytes {
			return invalid("a receipt is empty or larger than %d bytes", maxReceiptBytes)
		}
	}
	for _, n := range append(slices.Clone(b.Checkpoints), b.Previous) {
		if len(n) > maxNoteBytes {
			return invalid("a checkpoint is larger than %d bytes", maxNoteBytes)
		}
	}
	for i, e := range b.Entries {
		if err := e.check(); err != nil {
			return err
		}
		if i > 0 && e.Seq <= b.Entries[i-1].Seq {
			return invalid("entries must be in increasing seq order")
		}
	}
	for _, p := range b.Inclusion {
		if p.Seq < 1 || p.Size < 1 || len(p.Proof) > maxProofHashes || !hashes(p.Proof) {
			return invalid("malformed inclusion proof for seq %d", p.Seq)
		}
	}
	for _, p := range b.Consistency {
		if p.From < 1 || p.To < 1 || len(p.Proof) > 2*maxProofHashes || !hashes(p.Proof) {
			return invalid("malformed consistency proof")
		}
	}
	if a := b.Anchor; a != nil {
		if a.Checkpoint < 1 || len(a.Nonce) != anchor.NonceSize || len(a.Leaves) == 0 || len(a.Leaves) > anchor.MaxLeaves ||
			!hashes(a.Leaves) || len(a.Statement) == 0 || len(a.Statement) > anchor.MaxStatementBytes ||
			len(a.Signature) == 0 || len(a.Signature) > 256 || len(a.RekorEntry) > anchor.MaxEntryBytes ||
			len(a.Timestamp) > anchor.MaxTokenBytes {
			return invalid("malformed anchor")
		}
	}
	return nil
}

func (e Entry) check() error {
	switch {
	case e.Seq < 1:
		return invalid("entry seq must be positive")
	case len(e.PrevHash) != merkle.HashSize || len(e.EntryHash) != merkle.HashSize:
		return invalid("seq %d: prev_hash and entry_hash must be 32 bytes", e.Seq)
	case (len(e.Body) == 0) == (e.Removed == nil):
		return invalid("seq %d: exactly one of body and body_removed", e.Seq)
	case len(e.Body) > domain.MaxBodyBytes+1024:
		return invalid("seq %d: body too large", e.Seq)
	}
	return nil
}

func hashes(hs [][]byte) bool {
	for _, h := range hs {
		if len(h) != merkle.HashSize {
			return false
		}
	}
	return true
}

func toHashes(hs [][]byte) []merkle.Hash {
	out := make([]merkle.Hash, len(hs))
	for i, h := range hs {
		copy(out[i][:], h)
	}
	return out
}

func truncate(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

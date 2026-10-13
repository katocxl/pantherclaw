// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package bundletest builds verify bundles for tests: an Issuer plays a
// PantherClaw deployment that chains ledger entries with decision receipts,
// keeps the org's Merkle tree, signs checkpoints, and anchors them in a
// local fake Rekor v2 log with a fake RFC 3161 authority (anchortest). It
// never touches the network.
package bundletest

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
	"github.com/katocxl/pantherclaw/internal/evidence/anchor/anchortest"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/evidence/note"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// LogOrigin is the issuer's evidence.log_origin.
const LogOrigin = "evidence.test"

// IssuedAt is when the issuer's receipts are issued.
var IssuedAt = time.Date(2026, 10, 10, 8, 30, 0, 0, time.UTC)

// Issuer is a fake deployment with one org.
type Issuer struct {
	T      testing.TB
	Org    ids.OrgID
	Origin string

	receipts  *jws.Signer
	cpKey     ed25519.PrivateKey
	pqKey     *mldsa.PrivateKey
	anchorKey *ecdsa.PrivateKey
	anchorDER []byte
	Rekor     *anchortest.Rekor
	CA        *anchortest.CA
	TSA       *anchortest.TSA
	CoSign    bool // sign checkpoints with ML-DSA-65 as well
	Entries   []bundle.Entry
	Receipts  []string
	tiles     *merkle.MemoryTiles
	notes     map[uint64][]byte
}

// NewIssuer returns an issuer with fresh keys, an empty ledger, a fake log
// and a fake timestamp authority.
func NewIssuer(t testing.TB) *Issuer {
	t.Helper()
	_, rpriv, _ := ed25519.GenerateKey(rand.Reader)
	rs, err := jws.NewSigner("receipts-test-1", rpriv)
	if err != nil {
		t.Fatal(err)
	}
	_, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	pq, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	ak, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ader, _ := x509.MarshalPKIXPublicKey(&ak.PublicKey)
	org := ids.New[ids.Org]()
	ca := anchortest.NewCA(t, anchortest.CertOpts{})
	return &Issuer{
		T: t, Org: org, Origin: LogOrigin + "/org/" + org.String(),
		receipts: rs, cpKey: cpriv, pqKey: pq, anchorKey: ak, anchorDER: ader,
		Rekor: anchortest.NewRekor(t, "ed25519"), CA: ca, TSA: &anchortest.TSA{T: t, CA: ca},
		tiles: merkle.NewMemoryTiles(), notes: map[uint64][]byte{},
	}
}

// Append chains n entries, each recording a new decision receipt by its
// receipt_sha256, as the finalization does.
func (i *Issuer) Append(n int) {
	for range n {
		seq := int64(len(i.Entries)) + 1
		txn := ids.NewV7().String()
		payload, _ := json.Marshal(map[string]any{
			"iss": "https://pantherclaw.test", "jti": txn + "/1", "iat": IssuedAt.Unix(),
			"pap": map[string]any{"v": 1, "kind": "decision", "org": i.Org.String(), "txn": txn, "decision": "ALLOW"},
		}, json.Deterministic(true))
		r, err := i.receipts.Sign("pap-decision+jwt", payload)
		if err != nil {
			i.T.Fatal(err)
		}
		sum := sha256.Sum256([]byte(r))
		body, err := domain.CanonicalBody(map[string]string{"txn": txn, "decision": "ALLOW", "receipt_sha256": hex.EncodeToString(sum[:])})
		if err != nil {
			i.T.Fatal(err)
		}
		i.Receipts = append(i.Receipts, r)
		i.Entries = append(i.Entries, bundle.Entry{
			Seq: seq, ID: ids.NewV7().String(), Kind: "authz.decision", Actor: domain.Actor{Type: "gateway", ID: "gw-1"},
			TS: domain.Timestamp(IssuedAt.Add(time.Duration(seq) * time.Second)), Body: jsontext.Value(body),
		})
	}
	i.rechain(int64(len(i.Entries)) - int64(n) + 1)
}

// rechain recomputes the links from seq on and rebuilds the tree.
func (i *Issuer) rechain(from int64) {
	prev := domain.GenesisHash
	if from > 1 {
		prev = i.Entries[from-2].EntryHash
	}
	for k := from - 1; k < int64(len(i.Entries)); k++ {
		e := &i.Entries[k]
		id, _ := ids.ParseUUID(e.ID)
		ts, _ := time.Parse("2006-01-02T15:04:05.000000Z", e.TS)
		de := domain.Entry{Org: i.Org, ID: id, Kind: e.Kind, Actor: e.Actor, OccurredAt: ts, Body: []byte(e.Body)}
		l, err := domain.Next(e.Seq-1, prev, de)
		if err != nil {
			i.T.Fatal(err)
		}
		e.PrevHash, e.EntryHash = l.PrevHash, l.EntryHash
		prev = l.EntryHash
	}
	i.tiles = merkle.NewMemoryTiles()
	for _, e := range i.Entries {
		if err := i.tiles.Append(context.Background(), merkle.LeafHash(e.EntryHash)); err != nil {
			i.T.Fatal(err)
		}
	}
}

// Size is the ledger's size.
func (i *Issuer) Size() uint64 { return uint64(len(i.Entries)) }

// Checkpoint signs a checkpoint of the current tree with the checkpoints
// key (and the ML-DSA-65 key when CoSign is set) and returns the note.
func (i *Issuer) Checkpoint() []byte { return i.CheckpointAt(i.Size()) }

// CheckpointAt signs a checkpoint of the tree of an earlier size.
func (i *Issuer) CheckpointAt(size uint64) []byte {
	ctx := context.Background()
	root, err := merkle.Root(ctx, i.tiles, size)
	if err != nil {
		i.T.Fatal(err)
	}
	s, _ := note.NewEd25519Signer(i.Origin, i.cpKey)
	signers := []note.Signer{s}
	if i.CoSign {
		pq, _ := note.NewMLDSA65Signer(note.MLDSA65KeyName(i.Origin), i.pqKey)
		signers = append(signers, pq)
	}
	n, err := note.SignCheckpoint(note.Checkpoint{Origin: i.Origin, Size: size, Root: root}, signers...)
	if err != nil {
		i.T.Fatal(err)
	}
	i.notes[size] = n
	return n
}

// Anchor anchors the checkpoint of size: the org's blinded leaf among three
// other orgs' leaves, the statement signed by the anchors key, entered in
// the fake Rekor v2 log and timestamped by the fake authority.
func (i *Issuer) Anchor(size uint64) *bundle.Anchor {
	ctx := context.Background()
	cp, ok := i.notes[size]
	if !ok {
		i.T.Fatalf("no checkpoint of size %d", size)
	}
	nonce, _ := anchor.NewNonce()
	leaves := []merkle.Hash{anchor.Leaf(nonce, cp)}
	for range 3 {
		other, _ := anchor.NewNonce()
		leaves = append(leaves, anchor.Leaf(other, []byte("another org's checkpoint")))
	}
	tree, err := anchor.NewTree(leaves)
	if err != nil {
		i.T.Fatal(err)
	}
	signed, err := anchor.SignStatement(i.anchorKey, anchor.Statement{
		Origin: LogOrigin, Period: anchortest.TSANow.Truncate(time.Hour), Size: tree.Size(), Root: tree.Root(),
	})
	if err != nil {
		i.T.Fatal(err)
	}
	log, err := anchor.NewLog(anchortest.RekorOrigin, i.Rekor.PublicKey)
	if err != nil {
		i.T.Fatal(err)
	}
	rc := &anchor.RekorClient{URL: anchortest.RekorURL, HTTP: i.Rekor, Log: log}
	_, entry, err := rc.Submit(ctx, anchor.FromSigned(signed, i.anchorDER))
	if err != nil {
		i.T.Fatal(err)
	}
	tv, err := anchor.NewTSAVerifier(i.CA.Chain)
	if err != nil {
		i.T.Fatal(err)
	}
	tc := &anchor.TSAClient{URL: anchortest.TSAURL, HTTP: i.TSA, Verifier: tv}
	ts, _, err := tc.Timestamp(ctx, signed.Signature)
	if err != nil {
		i.T.Fatal(err)
	}
	a := &bundle.Anchor{
		Checkpoint: size, Nonce: nonce[:], Statement: signed.Statement, Signature: signed.Signature,
		RekorEntry: jsontext.Value(entry), Timestamp: ts,
	}
	for _, l := range tree.Leaves() {
		a.Leaves = append(a.Leaves, slices.Clone(l[:]))
	}
	return a
}

// Bundle assembles a bundle of every entry and receipt, every signed
// checkpoint, an inclusion proof of each entry in the smallest checkpoint
// that covers it, and consistency proofs between adjacent checkpoints.
func (i *Issuer) Bundle() *bundle.Bundle {
	ctx := context.Background()
	b := &bundle.Bundle{
		Format: bundle.Format, Org: i.Org.String(), Origin: i.Origin,
		Receipts: slices.Clone(i.Receipts), Entries: slices.Clone(i.Entries),
	}
	sizes := slices.Sorted(func(yield func(uint64) bool) {
		for s := range i.notes {
			if !yield(s) {
				return
			}
		}
	})
	for _, s := range sizes {
		b.Checkpoints = append(b.Checkpoints, string(i.notes[s]))
	}
	for _, e := range i.Entries {
		seq := uint64(e.Seq) //nolint:gosec // G115: positive
		k, _ := slices.BinarySearch(sizes, seq)
		if k == len(sizes) {
			continue
		}
		p, err := merkle.InclusionProof(ctx, i.tiles, seq-1, sizes[k])
		if err != nil {
			i.T.Fatal(err)
		}
		b.Inclusion = append(b.Inclusion, bundle.Inclusion{Seq: e.Seq, Size: sizes[k], Proof: raw(p)})
	}
	for k := 1; k < len(sizes); k++ {
		b.Consistency = append(b.Consistency, i.Consistency(sizes[k-1], sizes[k]))
	}
	return b
}

// Consistency returns the issuer's consistency proof from size a to b.
func (i *Issuer) Consistency(a, b uint64) bundle.Consistency {
	p, err := merkle.ConsistencyProof(context.Background(), i.tiles, a, b)
	if err != nil {
		i.T.Fatal(err)
	}
	return bundle.Consistency{From: a, To: b, Proof: raw(p)}
}

func raw(hs []merkle.Hash) [][]byte {
	out := make([][]byte, len(hs))
	for k, h := range hs {
		out[k] = slices.Clone(h[:])
	}
	return out
}

// Rewrite returns an insider's copy of the issuer whose history is changed
// from seq on: that entry's body differs, every later link is recomputed
// and the tree is rebuilt, with the same keys. It has no checkpoints until
// it signs them again with the real key.
func (i *Issuer) Rewrite(seq int64) *Issuer {
	c := *i
	c.Entries = slices.Clone(i.Entries)
	body, err := domain.CanonicalBody(map[string]string{"decision": "DENY", "rewritten": "true"})
	if err != nil {
		i.T.Fatal(err)
	}
	c.Entries[seq-1].Body = jsontext.Value(body)
	c.notes = map[uint64][]byte{}
	c.rechain(seq)
	return &c
}

// PQKey returns the issuer's ML-DSA-65 key, pinned as checkpoints-pq-test-1
// (pack manifests are co-signed with it too).
func (i *Issuer) PQKey() *mldsa.PrivateKey { return i.pqKey }

// Trust returns the trust file pinning the issuer's keys.
func (i *Issuer) Trust() []byte {
	nb := IssuedAt.Add(-30 * 24 * time.Hour)
	t := bundle.Trust{Format: bundle.TrustFormat, Issuer: "https://pantherclaw.test", LogOrigin: LogOrigin, Keys: []bundle.TrustedKey{
		{KID: i.receipts.KeyID(), Purpose: bundle.PurposeReceipts, Algorithm: bundle.AlgEdDSA, PublicKey: i.receipts.Public(), NotBefore: nb, State: bundle.StateActive},
		{KID: "checkpoints-test-1", Purpose: bundle.PurposeCheckpoints, Algorithm: bundle.AlgEdDSA, PublicKey: i.cpKey.Public().(ed25519.PublicKey), NotBefore: nb, State: bundle.StateActive},
		{KID: "checkpoints-pq-test-1", Purpose: bundle.PurposeCheckpointsPQ, Algorithm: bundle.AlgMLDSA65, PublicKey: i.pqKey.PublicKey().Bytes(), NotBefore: nb, State: bundle.StateActive},
		{KID: "anchors-test-1", Purpose: bundle.PurposeAnchors, Algorithm: bundle.AlgES256, PublicKey: i.anchorDER, NotBefore: nb, State: bundle.StateActive},
	}}
	b, err := json.Marshal(t)
	if err != nil {
		i.T.Fatal(err)
	}
	return b
}

// SigstoreRoot returns a trusted_root.json for the fake log and authority.
func (i *Issuer) SigstoreRoot() []byte {
	b, err := json.Marshal(map[string]any{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": []any{map[string]any{
			"baseUrl": "https://" + anchortest.RekorOrigin, "hashAlgorithm": "SHA2_256",
			"publicKey": map[string]any{"rawBytes": i.Rekor.PublicKey, "keyDetails": "PKIX_ED25519"},
		}},
		"timestampAuthorities": []any{map[string]any{
			"certChain": map[string]any{"certificates": []any{
				map[string]any{"rawBytes": i.CA.Cert.Raw}, map[string]any{"rawBytes": i.CA.Root.Raw},
			}},
			"validFor": map[string]any{"start": "2026-01-01T00:00:00Z"},
		}},
	})
	if err != nil {
		i.T.Fatal(err)
	}
	return b
}

// Note returns the issuer's signed checkpoint of size.
func (i *Issuer) Note(size uint64) []byte {
	n, ok := i.notes[size]
	if !ok {
		i.T.Fatal("no checkpoint of size " + strconv.FormatUint(size, 10))
	}
	return n
}

// Encode returns b as canonical JSON.
func Encode(t testing.TB, b *bundle.Bundle) []byte {
	t.Helper()
	out, err := bundle.Encode(b)
	if err != nil {
		t.Fatal(fmt.Errorf("encode bundle: %w", err))
	}
	return out
}

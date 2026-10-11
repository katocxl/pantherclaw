// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/evidence/note"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Options are a verification's inputs besides the bundle. Nothing is ever
// fetched: Trust holds the only keys that count.
type Options struct {
	Trust *Trust
	// Sigstore holds the transparency logs and timestamp authorities; when
	// nil, an anchor's log entry and timestamp are not available.
	Sigstore *SigstoreRoot
	// Previous is a checkpoint note the user saved earlier (a witness).
	Previous []byte
}

// receiptTypes are the JOSE types of receipts (PAP-1 §9.1–9.3).
var receiptTypes = map[string]bool{"pap-decision+jwt": true, "pap-execution+jwt": true, "pap-effect+jwt": true}

// tsLayout is the ledger's timestamp form (domain.Timestamp).
const tsLayout = "2006-01-02T15:04:05.000000Z"

type noteKey struct {
	key *TrustedKey
	v   note.Verifier
}

type checkpoint struct {
	note.Checkpoint
	raw []byte
}

type verifier struct {
	b       *Bundle
	o       Options
	r       *Report
	org     ids.OrgID
	origin  string
	keys    []noteKey             // checkpoints keys (Ed25519)
	pqKeys  []noteKey             // checkpoints_pq keys (ML-DSA-65)
	cps     map[uint64]checkpoint // verified checkpoints by size
	sizes   []uint64              // their sizes, ascending
	digests map[string]int64      // receipt_sha256 of verified entries → seq
	// snapshots are the verified coverage snapshot entries by snapshot id
	// (HR-217).
	snapshots map[string]snapshotEntry
}

// Verify checks a bundle offline against the pinned keys and returns the
// report of every check (HR-196). It never fails as a whole: problems are
// failed checks.
func Verify(b *Bundle, o Options) *Report {
	r := newReport()
	if b == nil || o.Trust == nil {
		r.add("bundle.format", "", Failed, "a bundle and a trust file are required")
		return r
	}
	v := &verifier{
		b: b, o: o, r: r, cps: map[uint64]checkpoint{}, digests: map[string]int64{}, snapshots: map[string]snapshotEntry{},
	}
	v.checkOrigin()
	v.checkpoints()
	v.consistency()
	v.witness("witness.bundle", []byte(b.Previous), false)
	v.witness("witness.previous", o.Previous, true)
	v.entries()
	v.receipts()
	v.anchor()
	return r
}

func (v *verifier) checkOrigin() {
	org, err := ids.Parse[ids.Org](v.b.Org)
	v.org = org
	v.origin = v.o.Trust.LogOrigin + "/org/" + v.b.Org
	switch {
	case err != nil:
		v.r.add("bundle.origin", "", Failed, "the org %q is not an id", truncate(v.b.Org))
	case v.b.Origin != v.origin:
		v.r.add("bundle.origin", "", Failed, "the bundle's origin %q is not %q, from your trust file", truncate(v.b.Origin), v.origin)
	default:
		v.r.add("bundle.origin", "", Passed, "evidence of org %s at %s", v.b.Org, v.o.Trust.LogOrigin)
	}
	for _, k := range v.o.Trust.keys(PurposeCheckpoints) {
		if nv, err := note.NewEd25519Verifier(v.origin, k.ed); err == nil {
			v.keys = append(v.keys, noteKey{k, nv})
		}
	}
	for _, k := range v.o.Trust.keys(PurposeCheckpointsPQ) {
		if nv, err := note.NewMLDSA65Verifier(note.MLDSA65KeyName(v.origin), k.mldsa); err == nil {
			v.pqKeys = append(v.pqKeys, noteKey{k, nv})
		}
	}
}

func verifiers(ks []noteKey) []note.Verifier {
	out := make([]note.Verifier, len(ks))
	for i, k := range ks {
		out[i] = k.v
	}
	return out
}

// signer returns the pinned key whose signature verified.
func signer(ks []noteKey, verified []note.Signature) *TrustedKey {
	for _, k := range ks {
		if note.SignedBy(verified, k.v) {
			return k.key
		}
	}
	return nil
}

// openCheckpoint verifies a checkpoint note with the pinned checkpoints keys.
func (v *verifier) openCheckpoint(raw []byte) (note.Checkpoint, *TrustedKey, error) {
	c, verified, err := note.OpenCheckpoint(raw, v.origin, verifiers(v.keys)...)
	switch {
	case errors.Is(err, note.ErrUnverified):
		return c, nil, errors.New("not signed by a checkpoints key in your trust file")
	case err != nil:
		return c, nil, err
	}
	k := signer(v.keys, verified)
	switch {
	case k == nil:
		return c, nil, errors.New("not signed by a checkpoints key in your trust file")
	case k.State == StateRevoked:
		return c, nil, fmt.Errorf("signed by key %s, which is revoked", k.KID)
	}
	return c, k, nil
}

func (v *verifier) checkpoints() {
	if len(v.b.Checkpoints) == 0 {
		v.r.add("checkpoint.signature", "", NotAvailable, "the bundle has no checkpoint")
		return
	}
	for i, s := range v.b.Checkpoints {
		raw := []byte(s)
		subject := fmt.Sprintf("checkpoint %d", i+1)
		c, k, err := v.openCheckpoint(raw)
		if err != nil {
			v.r.add("checkpoint.signature", subject, Failed, "%v", err)
			continue
		}
		subject = fmt.Sprintf("size %d", c.Size)
		if prev, ok := v.cps[c.Size]; ok && !prev.Root.Equal(c.Root) {
			v.r.add("checkpoint.signature", subject, Failed, "two signed checkpoints of size %d have different roots (a forked history)", c.Size)
			continue
		}
		v.r.add("checkpoint.signature", subject, Passed, "Ed25519 signature by checkpoints key %s", k.KID)
		v.cps[c.Size] = checkpoint{c, raw}
		v.cosignature(subject, raw)
	}
	for s := range v.cps {
		v.sizes = append(v.sizes, s)
	}
	slices.Sort(v.sizes)
}

// cosignature checks the optional ML-DSA-65 line (decision 6).
func (v *verifier) cosignature(subject string, raw []byte) {
	if len(v.pqKeys) == 0 {
		v.r.add("checkpoint.cosignature", subject, NotAvailable, "no ML-DSA-65 checkpoint key in your trust file")
		return
	}
	_, verified, err := note.Open(raw, verifiers(v.pqKeys)...)
	switch {
	case errors.Is(err, note.ErrUnverified):
		v.r.add("checkpoint.cosignature", subject, NotAvailable, "no ML-DSA-65 co-signature from a pinned key")
	case err != nil:
		v.r.add("checkpoint.cosignature", subject, Failed, "%v", err)
	default:
		k := signer(v.pqKeys, verified)
		if k == nil {
			v.r.add("checkpoint.cosignature", subject, NotAvailable, "no ML-DSA-65 co-signature from a pinned key")
			return
		}
		if k.State == StateRevoked {
			v.r.add("checkpoint.cosignature", subject, Failed, "ML-DSA-65 key %s is revoked", k.KID)
			return
		}
		v.r.add("checkpoint.cosignature", subject, Passed, "ML-DSA-65 co-signature by %s", k.KID)
	}
}

// consistencyProof finds the bundle's proof from size a to size b.
func (v *verifier) consistencyProof(a, b uint64) ([]merkle.Hash, bool) {
	for _, p := range v.b.Consistency {
		if p.From == a && p.To == b {
			return toHashes(p.Proof), true
		}
	}
	return nil, false
}

// prove checks that the tree of size b with rootB extends the tree of size
// a with rootA (a ≤ b).
func (v *verifier) prove(a, b uint64, rootA, rootB merkle.Hash) (Status, string) {
	if a == b {
		if rootA.Equal(rootB) {
			return Passed, fmt.Sprintf("the same checkpoint of size %d", a)
		}
		return Failed, fmt.Sprintf("two checkpoints of size %d have different roots (a forked history)", a)
	}
	p, ok := v.consistencyProof(a, b)
	if !ok {
		return Failed, fmt.Sprintf("the bundle has no consistency proof from size %d to size %d", a, b)
	}
	if err := merkle.VerifyConsistency(a, b, p, rootA, rootB); err != nil {
		return Failed, fmt.Sprintf("size %d does not extend size %d: a rewritten or forked history (%v)", b, a, err)
	}
	return Passed, fmt.Sprintf("size %d extends size %d", b, a)
}

func (v *verifier) consistency() {
	for i := 1; i < len(v.sizes); i++ {
		a, b := v.sizes[i-1], v.sizes[i]
		s, d := v.prove(a, b, v.cps[a].Root, v.cps[b].Root)
		v.r.add("checkpoint.consistency", fmt.Sprintf("size %d → %d", a, b), s, "%s", d)
	}
}

// witness checks a checkpoint saved earlier: it must verify with the pinned
// keys and be consistent with the bundle's checkpoints.
func (v *verifier) witness(name string, raw []byte, report bool) {
	if len(raw) == 0 {
		if report {
			v.r.add(name, "", NotAvailable, "no saved checkpoint given (--previous)")
		}
		return
	}
	w, _, err := v.openCheckpoint(raw)
	if err != nil {
		v.r.add(name, "", Failed, "the saved checkpoint does not verify: %v", err)
		return
	}
	subject := fmt.Sprintf("size %d", w.Size)
	for _, s := range slices.Backward(v.sizes) {
		c := v.cps[s]
		lo, hi, rootLo, rootHi := w.Size, s, w.Root, c.Root
		if s < w.Size {
			lo, hi, rootLo, rootHi = s, w.Size, c.Root, w.Root
		}
		if _, ok := v.consistencyProof(lo, hi); ok || lo == hi {
			st, d := v.prove(lo, hi, rootLo, rootHi)
			v.r.add(name, subject, st, "against the bundle's checkpoint of size %d: %s", s, d)
			return
		}
	}
	v.r.add(name, subject, Failed, "the bundle does not prove that its checkpoints extend the checkpoint of size %d you saved", w.Size)
}

func (v *verifier) entries() {
	proofs := map[int64][]Inclusion{}
	for _, p := range v.b.Inclusion {
		proofs[p.Seq] = append(proofs[p.Seq], p)
	}
	var prev *Entry
	for i := range v.b.Entries {
		e := &v.b.Entries[i]
		subject := fmt.Sprintf("seq %d", e.Seq)
		st, d := v.link(e, prev)
		v.r.add("entry.link", subject, st, "%s", d)
		v.inclusion(e, subject, proofs[e.Seq])
		prev = e
	}
}

// link recomputes the entry's hash from the entry and prev_hash, and checks
// it links to the previous entry when that one is in the bundle.
func (v *verifier) link(e, prev *Entry) (Status, string) {
	switch {
	case e.Seq == 1 && !bytes.Equal(e.PrevHash, domain.GenesisHash):
		return Failed, "the first entry does not start from the genesis hash"
	case prev != nil && prev.Seq == e.Seq-1 && !bytes.Equal(e.PrevHash, prev.EntryHash):
		return Failed, fmt.Sprintf("prev_hash is not the entry_hash of seq %d (an entry was changed, inserted or removed)", prev.Seq)
	case e.Removed != nil:
		return NotAvailable, fmt.Sprintf("body removed by retention policy %s on %s; its hash stays chained and in the tree",
			truncate(e.Removed.Policy), truncate(e.Removed.At))
	}
	id, err := ids.ParseUUID(e.ID)
	if err != nil {
		return Failed, "the entry id is not a UUID"
	}
	ts, err := time.Parse(tsLayout, e.TS)
	if err != nil || domain.Timestamp(ts) != e.TS {
		return Failed, "the entry time is not in the ledger's form"
	}
	body := jsontext.Value(bytes.Clone(e.Body))
	if err := body.Canonicalize(); err != nil {
		return Failed, "the entry body is not valid JSON"
	}
	entry := domain.Entry{Org: v.org, ID: id, Kind: e.Kind, Actor: e.Actor, OccurredAt: ts, Body: body}
	c, err := entry.Canonical(e.Seq)
	if err != nil {
		return Failed, err.Error()
	}
	if !bytes.Equal(domain.LinkHash(e.PrevHash, c), e.EntryHash) {
		return Failed, "entry_hash does not match the entry: the entry or its link was changed"
	}
	var ref struct {
		Receipt string `json:"receipt_sha256"`
	}
	if json.Unmarshal(body, &ref) == nil && ref.Receipt != "" {
		v.digests[ref.Receipt] = e.Seq
	}
	if e.Kind == SnapshotKind {
		v.noteSnapshot(e, body)
	}
	return Passed, "entry_hash recomputed from the entry and prev_hash"
}

func (v *verifier) inclusion(e *Entry, subject string, proofs []Inclusion) {
	seq := uint64(e.Seq) //nolint:gosec // G115: decoding checked seq ≥ 1
	i, _ := slices.BinarySearch(v.sizes, seq)
	if i == len(v.sizes) {
		v.r.add("entry.inclusion", subject, NotAvailable, "newer than the bundle's checkpoints (not in a checkpoint yet)")
		return
	}
	leaf := merkle.LeafHash(e.EntryHash)
	for _, p := range proofs {
		c, ok := v.cps[p.Size]
		if !ok || p.Size < seq {
			continue
		}
		if err := merkle.VerifyInclusion(leaf, seq-1, p.Size, toHashes(p.Proof), c.Root); err != nil {
			v.r.add("entry.inclusion", subject, Failed, "not in the checkpoint of size %d: %v", p.Size, err)
			return
		}
		v.r.add("entry.inclusion", subject, Passed, "in the checkpoint of size %d", p.Size)
		return
	}
	v.r.add("entry.inclusion", subject, Failed, "no inclusion proof, although the checkpoint of size %d covers it", v.sizes[i])
}

func (v *verifier) receipts() {
	for i, compact := range v.b.Receipts {
		subject := fmt.Sprintf("receipt %d", i+1)
		st, d, subj, payload := v.receipt(compact)
		if subj != "" {
			subject = subj
		}
		v.r.add("receipt.signature", subject, st, "%s", d)
		if st != Passed {
			continue
		}
		sum := sha256.Sum256([]byte(compact))
		if seq, ok := v.digests[hex.EncodeToString(sum[:])]; ok {
			v.r.add("receipt.ledger", subject, Passed, "recorded by the chained entry at seq %d", seq)
		} else {
			v.r.add("receipt.ledger", subject, NotAvailable, "no verified entry in this bundle records it")
		}
		v.coverage(subject, payload)
	}
}

// receipt checks one receipt: an allowed type, EdDSA only, a pinned
// receipts key, valid when the receipt was issued (iat), of this org.
func (v *verifier) receipt(compact string) (Status, string, string, []byte) {
	kid, typ, err := jws.Unverified(compact)
	if err != nil {
		return Failed, "not a compact JWS", "", nil
	}
	if !receiptTypes[typ] {
		return Failed, fmt.Sprintf("type %q is not a receipt", truncate(typ)), "", nil
	}
	k := v.o.Trust.key(PurposeReceipts, kid)
	if k == nil {
		return Failed, fmt.Sprintf("signed by key %q, which is not in your trust file", truncate(kid)), "", nil
	}
	jv, err := jws.NewVerifier(typ, map[string]ed25519.PublicKey{kid: k.ed})
	if err != nil {
		return Failed, err.Error(), "", nil
	}
	payload, _, err := jv.Verify(compact)
	if err != nil {
		return Failed, "the EdDSA signature does not verify", "", nil
	}
	var claims struct {
		Jti string `json:"jti"`
		Iat *int64 `json:"iat"`
		Pap struct {
			Org string `json:"org"`
		} `json:"pap"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Iat == nil {
		return Failed, "the receipt's claims are malformed or have no iat", "", nil
	}
	subject := strings.TrimSuffix(typ, "+jwt") + " " + truncate(claims.Jti)
	at := time.Unix(*claims.Iat, 0).UTC()
	switch {
	case !k.ValidAt(at):
		return Failed, fmt.Sprintf("key %s was not valid when the receipt was issued (%s; state %s)", kid, at.Format(time.RFC3339), k.State), subject, nil
	case claims.Pap.Org != "" && claims.Pap.Org != v.b.Org:
		return Failed, "the receipt belongs to another org", subject, nil
	}
	return Passed, fmt.Sprintf("EdDSA signature by %s, valid when issued (%s)", kid, at.Format(time.RFC3339)), subject, payload
}

func (v *verifier) anchor() {
	a := v.b.Anchor
	if a == nil {
		v.r.add("anchor", "", NotAvailable, "not anchored")
		return
	}
	subject := fmt.Sprintf("checkpoint size %d", a.Checkpoint)
	leaves := toHashes(a.Leaves)
	if cp, ok := v.cps[a.Checkpoint]; !ok {
		v.r.add("anchor.leaf", subject, Failed, "the anchored checkpoint is not among the bundle's verified checkpoints")
	} else {
		var nonce anchor.Nonce
		copy(nonce[:], a.Nonce)
		leaf := anchor.Leaf(nonce, cp.raw)
		if slices.ContainsFunc(leaves, leaf.Equal) {
			v.r.add("anchor.leaf", subject, Passed, "the org's blinded leaf for this checkpoint is in the anchor")
		} else {
			v.r.add("anchor.leaf", subject, Failed, "the anchor does not contain the org's leaf for this checkpoint")
		}
	}

	key, stmt := v.statement(subject)
	if tree, err := anchor.TreeFromOrderedLeaves(leaves); err != nil {
		v.r.add("anchor.root", subject, Failed, "%v", err)
	} else if s, err := anchor.ParseStatement(a.Statement); err != nil || !tree.Root().Equal(s.Root) || tree.Size() != s.Size {
		v.r.add("anchor.root", subject, Failed, "the anchor's leaves do not build the root of its statement")
	} else {
		v.r.add("anchor.root", subject, Passed, "the %d leaves build the statement's global root", tree.Size())
	}
	if key == nil {
		v.r.add("anchor.log", subject, NotAvailable, "needs a statement signed by a pinned anchors key")
		v.r.add("anchor.timestamp", subject, NotAvailable, "needs a statement signed by a pinned anchors key")
		return
	}
	v.anchorLog(subject, a, key)
	v.anchorTimestamp(subject, a, key, stmt)
}

// statement checks the statement's signature with the pinned anchors keys
// and its origin.
func (v *verifier) statement(subject string) (*TrustedKey, anchor.Statement) {
	a := v.b.Anchor
	for _, k := range v.o.Trust.keys(PurposeAnchors) {
		s, err := anchor.VerifyStatement(k.PublicKey, a.Statement, a.Signature)
		if err != nil {
			continue
		}
		switch {
		case k.State == StateRevoked:
			v.r.add("anchor.signature", subject, Failed, "signed by anchors key %s, which is revoked", k.KID)
		case s.Origin != v.o.Trust.LogOrigin:
			v.r.add("anchor.signature", subject, Failed, "the statement is for origin %q, not %q", truncate(s.Origin), v.o.Trust.LogOrigin)
		default:
			v.r.add("anchor.signature", subject, Passed, "ECDSA P-256 signature by anchors key %s", k.KID)
			return k, s
		}
		return nil, s
	}
	v.r.add("anchor.signature", subject, Failed, "the statement is not signed by an anchors key in your trust file")
	return nil, anchor.Statement{}
}

func (v *verifier) anchorLog(subject string, a *Anchor, key *TrustedKey) {
	switch {
	case v.o.Sigstore == nil:
		v.r.add("anchor.log", subject, NotAvailable, "no Sigstore trusted root given (--sigstore-trusted-root)")
		return
	case len(a.RekorEntry) == 0:
		v.r.add("anchor.log", subject, NotAvailable, "the anchor has no transparency log entry")
		return
	}
	e, err := anchor.ParseEntry(a.RekorEntry)
	if err != nil {
		v.r.add("anchor.log", subject, Failed, "%v", err)
		return
	}
	body, err := anchor.HashedRekord{Digest: sha256.Sum256(a.Statement), Signature: a.Signature, PublicKey: key.PublicKey}.CanonicalBody()
	if err != nil {
		v.r.add("anchor.log", subject, Failed, "%v", err)
		return
	}
	var last error
	for _, l := range v.o.Sigstore.Logs {
		cp, err := anchor.VerifyEntry(e, l, body)
		if err == nil {
			v.r.add("anchor.log", subject, Passed, "entry %d of %s, in its signed checkpoint of size %d", e.LogIndex, l.Origin, cp.Size)
			return
		}
		last = err
	}
	v.r.add("anchor.log", subject, Failed, "the entry does not verify against the logs of your Sigstore trusted root (%v)", last)
}

func (v *verifier) anchorTimestamp(subject string, a *Anchor, key *TrustedKey, stmt anchor.Statement) {
	switch {
	case v.o.Sigstore == nil:
		v.r.add("anchor.timestamp", subject, NotAvailable, "no Sigstore trusted root given (--sigstore-trusted-root)")
		return
	case len(a.Timestamp) == 0:
		v.r.add("anchor.timestamp", subject, NotAvailable, "the anchor has no timestamp")
		return
	}
	var last error
	for _, t := range v.o.Sigstore.TSAs {
		ts, err := t.Verify(a.Timestamp, a.Signature)
		if err != nil {
			last = err
			continue
		}
		switch {
		case ts.Time.Before(stmt.Period):
			v.r.add("anchor.timestamp", subject, Failed, "timestamped %s, before its anchoring period", ts.Time.Format(time.RFC3339))
		case !key.ValidAt(ts.Time):
			v.r.add("anchor.timestamp", subject, Failed, "anchors key %s was not valid at the timestamp %s", key.KID, ts.Time.Format(time.RFC3339))
		default:
			v.r.add("anchor.timestamp", subject, Passed, "the anchor existed by %s (RFC 3161, %s)",
				ts.Time.UTC().Format(time.RFC3339), truncate(ts.Signer.Subject.String()))
		}
		return
	}
	v.r.add("anchor.timestamp", subject, Failed, "the timestamp does not verify against the authorities of your Sigstore trusted root (%v)", last)
}

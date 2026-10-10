// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package checkpoints signs each org's ledger checkpoints and re-verifies
// the org's whole chain daily (G0 M7 design decision 8, HR-111, HR-194).
//
// Each org's chain is an RFC 9162 Merkle tree over its chained entry hashes,
// stored as C2SP tlog tiles (internal/evidence/merkle). Checkpoint, in one
// tenant transaction holding the org's ledger head lock:
//
//  1. verifies the previous checkpoint's signed note against the stored row;
//  2. recomputes the chain links of every entry since it from the entries
//     themselves, so a row edited before sealing is caught;
//  3. appends the new leaves to the tiles and computes the new root;
//  4. checks an RFC 9162 consistency proof from the previous checkpoint's
//     tree to the new one;
//  5. signs a C2SP signed note (Ed25519 with the checkpoints key, plus the
//     ML-DSA-65 line when co-signing is on) and stores it.
//
// Verify recomputes the whole chain from genesis (ledger.VerifyEach) and the
// latest checkpoint's root from it, and checks the tiles give the same root.
//
// Any mismatch is an IntegrityError: nothing is signed, the org's
// evidence_integrity row becomes FAILED (which stops checkpointing until an
// operator investigates), security.evidence_integrity_failed is written to
// the org's audit ledger, and org and security admins are notified.
// Authorization never waits for any of this: receipts are still written and
// chained (design decision 20). After investigating, an operator resumes
// checkpointing with Reset (`pantherclaw-server evidence integrity reset`),
// which repairs nothing: the next checks run again.
package checkpoints

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/evidence/note"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/keystore"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// MaxLeavesPerCheckpoint caps the entries one checkpoint adds, so a long
// backlog becomes several checkpoints in bounded transactions.
const MaxLeavesPerCheckpoint = 1 << 16

const pageRows = 1000

// Failure codes: evidence_integrity.failure_code and the audit reason.
const (
	// CodeChainLink: an entry's recomputed link differs from the stored one,
	// or a position is missing (an entry edited, inserted or deleted).
	CodeChainLink = "CHAIN_LINK"
	// CodeChainHead: the chain does not end at the stored head.
	CodeChainHead = "CHAIN_HEAD"
	// CodeCheckpointInvalid: a stored checkpoint's note does not verify or
	// does not match its row.
	CodeCheckpointInvalid = "CHECKPOINT_INVALID"
	// CodeCheckpointMissing: the tiles hold more leaves than the latest
	// checkpoint covers (a checkpoint was deleted).
	CodeCheckpointMissing = "CHECKPOINT_MISSING"
	// CodeTreeInconsistent: the new tree does not extend the previous
	// checkpoint's tree.
	CodeTreeInconsistent = "TREE_INCONSISTENT"
	// CodeTreeMismatch: the tiles or the chain give another root than the
	// checkpoint, or tiles are missing.
	CodeTreeMismatch = "TREE_MISMATCH"
)

// Checks name what found a failure.
const (
	CheckCheckpoint = "checkpoint"
	CheckDaily      = "daily verification"
)

// IntegrityError is a mismatch that stops checkpointing for an org.
type IntegrityError struct {
	Code   string
	Seq    int64 // the first position involved, when known
	Detail string
}

func (e *IntegrityError) Error() string {
	return fmt.Sprintf("checkpoints: integrity failure %s at seq %d: %s", e.Code, e.Seq, e.Detail)
}

func integrity(code string, seq int64, format string, args ...any) error {
	return &IntegrityError{Code: code, Seq: seq, Detail: fmt.Sprintf(format, args...)}
}

// ErrNoSigner reports a missing active checkpoints (or checkpoints_pq) key.
var ErrNoSigner = errors.New("checkpoints: no active signing key")

// Notifier enqueues notifications in the caller's transaction (M5).
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// Actor records integrity failures in the audit ledger.
var Actor = domain.Actor{Type: "system", ID: "evidence-integrity"}

// Service checkpoints and verifies orgs.
type Service struct {
	Pool *db.Pool
	Keys *keys.Registry
	// LogOrigin is evidence.log_origin: an org's checkpoints have the origin
	// LogOrigin + "/org/" + org id.
	LogOrigin string
	// Cosign adds the ML-DSA-65 co-signature (evidence.mldsa_cosign).
	Cosign bool
	// Notify may be nil (no notification).
	Notify Notifier
	Log    *slog.Logger
	// MaxLeaves caps the entries one checkpoint adds (0:
	// MaxLeavesPerCheckpoint).
	MaxLeaves int
}

// Origin returns the checkpoint origin of org (PAP-1 §9.4).
func (s *Service) Origin(org ids.OrgID) string { return s.LogOrigin + "/org/" + org.String() }

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return pclog.Discard()
	}
	return s.Log
}

// Result is what one call did.
type Result struct {
	Size    uint64 // the tree size of the checkpoint signed or verified
	Signed  bool   // Checkpoint signed a new checkpoint
	Stopped bool   // the org's integrity had failed before: nothing was done
}

// signers returns the note signers of org's checkpoints and their kids.
func (s *Service) signers(origin string) ([]note.Signer, string, *string, error) {
	ks := s.Keys.Keys(keys.PurposeCheckpoints)
	if len(ks) == 0 || ks[0].State != keys.StateActive {
		return nil, "", nil, fmt.Errorf("%w for %s", ErrNoSigner, keys.PurposeCheckpoints)
	}
	ed, err := note.NewEd25519Signer(origin, ks[0].Private.Reveal())
	if err != nil {
		return nil, "", nil, err
	}
	out := []note.Signer{ed}
	if !s.Cosign {
		return out, ks[0].KID, nil, nil
	}
	pq := s.Keys.AltKeys(keys.PurposeCheckpointsPQ)
	if len(pq) == 0 || pq[0].State != keys.StateActive {
		return nil, "", nil, fmt.Errorf("%w for %s", ErrNoSigner, keys.PurposeCheckpointsPQ)
	}
	priv, ok := pq[0].Private.Reveal().(*mldsa.PrivateKey)
	if !ok {
		return nil, "", nil, fmt.Errorf("%w for %s", ErrNoSigner, keys.PurposeCheckpointsPQ)
	}
	ms, err := note.NewMLDSA65Signer(note.MLDSA65KeyName(origin), priv)
	if err != nil {
		return nil, "", nil, err
	}
	kid := pq[0].KID
	return append(out, ms), ks[0].KID, &kid, nil
}

// verifiers returns the Ed25519 verifiers of every checkpoints key the
// keystore holds, retiring and revoked ones included: they check that a
// stored checkpoint is the note this deployment signed.
func (s *Service) verifiers(ctx context.Context, origin string) ([]note.Verifier, error) {
	ks, err := keystore.PublishedKeys(ctx, s.Pool, []keys.Purpose{keys.PurposeCheckpoints})
	if err != nil {
		return nil, err
	}
	out := make([]note.Verifier, 0, len(ks))
	for _, k := range ks {
		v, err := note.NewEd25519Verifier(origin, k.Public)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// openStored checks a stored checkpoint: its note verifies, has the org's
// origin, and states the row's size and root.
func openStored(row dbq.LatestCheckpointRow, origin string, vs []note.Verifier) (merkle.Hash, error) {
	c, _, err := note.OpenCheckpoint(row.Note, origin, vs...)
	if err != nil {
		return merkle.Hash{}, integrity(CodeCheckpointInvalid, row.TreeSize, "the checkpoint of size %d does not verify: %v", row.TreeSize, err)
	}
	root, err := merkle.HashFromBytes(row.RootHash)
	if err != nil || c.Size != uint64(row.TreeSize) || !c.Root.Equal(root) { //nolint:gosec // G115: tree_size > 0 (CHECK)
		return merkle.Hash{}, integrity(CodeCheckpointInvalid, row.TreeSize, "the checkpoint of size %d does not match its signed note", row.TreeSize)
	}
	return root, nil
}

// tiles reads an org's stored tiles in a transaction (merkle.TileReader).
type tiles struct {
	q   *dbq.Queries
	org ids.OrgID
}

func (t tiles) ReadTile(ctx context.Context, id merkle.TileID) ([]byte, error) {
	b, err := t.q.ReadLedgerTile(ctx, t.org, int16(id.Level), int64(id.Index)) //nolint:gosec // G115: level ≤ 63, index < 2^56
	if db.IsNoRows(err) || (err == nil && len(b) < id.Width*merkle.HashSize) {
		return nil, merkle.ErrTileNotFound
	}
	return b, err
}

// Checkpoint signs a new checkpoint of org's chain when it grew (see the
// package documentation). An integrity failure is reported and returned
// as an *IntegrityError after the transaction rolled back.
func (s *Service) Checkpoint(ctx context.Context, org ids.OrgID) (Result, error) {
	origin := s.Origin(org)
	signers, kid, pqKid, err := s.signers(origin)
	if err != nil {
		return Result{}, err
	}
	vs, err := s.verifiers(ctx, origin)
	if err != nil {
		return Result{}, err
	}
	maxLeaves := int64(s.MaxLeaves)
	if maxLeaves <= 0 {
		maxLeaves = MaxLeavesPerCheckpoint
	}
	var res Result
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		res = Result{}
		q := dbq.New(tx)
		head, err := q.LockLedgerHead(ctx, org)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		if st, err := q.GetEvidenceIntegrity(ctx, org); err == nil && st.State != "OK" {
			res.Stopped = true
			return nil
		} else if err != nil && !db.IsNoRows(err) {
			return err
		}
		var size int64
		var prevRoot merkle.Hash
		latest, err := q.LatestCheckpoint(ctx, org)
		switch {
		case err == nil:
			size = latest.TreeSize
			if prevRoot, err = openStored(latest, origin, vs); err != nil {
				return err
			}
		case !db.IsNoRows(err):
			return err
		}
		if head.Seq <= size {
			res.Size = uint64(size)
			return nil
		}
		if held, err := q.LedgerTileLeaves(ctx, org); err != nil && !db.IsNoRows(err) {
			return err
		} else if held > size {
			return integrity(CodeCheckpointMissing, size+1, "the tiles hold %d leaves but the latest checkpoint covers %d", held, size)
		}
		leaves, err := recompute(ctx, q, org, size, min(head.Seq, size+maxLeaves), head)
		if err != nil {
			return err
		}
		n := uint64(size) + uint64(len(leaves))
		root, err := s.extend(ctx, q, org, uint64(size), leaves, prevRoot)
		if err != nil {
			return err
		}
		signed, err := note.SignCheckpoint(note.Checkpoint{Origin: origin, Size: n, Root: root}, signers...)
		if err != nil {
			return err
		}
		if err := q.InsertCheckpoint(ctx, dbq.InsertCheckpointParams{
			OrgID: org, TreeSize: int64(n), RootHash: root[:], Note: signed, Kid: kid, PqKid: pqKid, //nolint:gosec // G115: n ≤ head.Seq
		}); err != nil {
			return err
		}
		res.Size, res.Signed = n, true
		return nil
	})
	var ie *IntegrityError
	if errors.As(err, &ie) {
		return Result{Stopped: true}, s.report(ctx, org, CheckCheckpoint, ie)
	}
	if err != nil {
		return Result{}, fmt.Errorf("checkpoints: org %s: %w", org, err)
	}
	return res, nil
}

// recompute verifies the chain links of positions after..upto from the
// entries and returns their leaf hashes. When upto is the head, the chain
// must end at the stored head hash.
func recompute(ctx context.Context, q *dbq.Queries, org ids.OrgID, after, upto int64, head dbq.LockLedgerHeadRow) ([]merkle.Hash, error) {
	start := domain.GenesisHash
	if after > 0 {
		h, err := q.LedgerEntryHashAt(ctx, org, after)
		if db.IsNoRows(err) {
			return nil, integrity(CodeChainLink, after, "the checkpointed position %d is missing from the chain", after)
		} else if err != nil {
			return nil, err
		}
		start = h
	}
	v, err := domain.NewVerifierAt(after, start)
	if err != nil {
		return nil, integrity(CodeChainLink, after, "%v", err)
	}
	leaves := make([]merkle.Hash, 0, upto-after)
	for pos := after; pos < upto; {
		rows, err := q.ChainedLedgerRange(ctx, dbq.ChainedLedgerRangeParams{OrgID: org, AfterSeq: pos, UptoSeq: upto, MaxRows: pageRows})
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			link := domain.Link{Seq: r.Seq, EntryID: r.ID, PrevHash: r.PrevHash, EntryHash: r.EntryHash}
			if r.BodyRemovedAt != nil {
				err = v.AddRemoved(link)
			} else {
				err = v.Add(link, domain.Entry{
					Org: org, ID: r.ID, Kind: r.Kind, Actor: domain.Actor{Type: r.ActorType, ID: r.ActorID},
					OccurredAt: r.OccurredAt, Body: r.Body,
				})
			}
			if err != nil {
				return nil, chainFailure(err)
			}
			leaf, err := merkle.HashFromBytes(r.EntryHash)
			if err != nil {
				return nil, integrity(CodeChainLink, r.Seq, "seq %d has a malformed entry hash", r.Seq)
			}
			leaves = append(leaves, merkle.LeafHash(leaf[:]))
			pos = r.Seq
		}
	}
	if seq, h := v.Head(); seq != upto {
		return nil, integrity(CodeChainLink, seq+1, "the chain ends at seq %d, before %d", seq, upto)
	} else if upto == head.Seq && !bytes.Equal(h, head.HeadHash) {
		return nil, integrity(CodeChainHead, upto, "the recomputed chain does not end at the stored head")
	}
	return leaves, nil
}

func chainFailure(err error) error {
	var ce *domain.ChainError
	if errors.As(err, &ce) {
		return integrity(CodeChainLink, ce.Seq, "%v", err)
	}
	if errors.Is(err, domain.ErrChainBroken) {
		return integrity(CodeChainHead, 0, "%v", err)
	}
	return err
}

// extend appends leaves to the tree of size old, stores the new tiles and
// returns the new root, after proving it consistent with prevRoot.
func (s *Service) extend(ctx context.Context, q *dbq.Queries, org ids.OrgID, old uint64, leaves []merkle.Hash, prevRoot merkle.Hash) (merkle.Hash, error) {
	r := tiles{q: q, org: org}
	added, err := merkle.AppendTiles(ctx, r, old, leaves)
	if errors.Is(err, merkle.ErrTileNotFound) {
		return merkle.Hash{}, integrity(CodeTreeMismatch, int64(old), "the tiles of the checkpointed tree are missing: %v", err) //nolint:gosec // G115: old ≤ 2^63
	} else if err != nil {
		return merkle.Hash{}, err
	}
	for _, t := range added {
		if err := q.InsertLedgerTile(ctx, dbq.InsertLedgerTileParams{
			OrgID: org, Level: int16(t.Level), TileIndex: int64(t.Index), Width: int16(t.Width), Hashes: t.Hashes, //nolint:gosec // G115: tile bounds
		}); err != nil {
			return merkle.Hash{}, err
		}
	}
	n := old + uint64(len(leaves))
	root, err := merkle.Root(ctx, r, n)
	if err != nil {
		return merkle.Hash{}, err
	}
	if old > 0 {
		proof, err := merkle.ConsistencyProof(ctx, r, old, n)
		if err != nil {
			return merkle.Hash{}, err
		}
		if err := merkle.VerifyConsistency(old, n, proof, prevRoot, root); err != nil {
			return merkle.Hash{}, integrity(CodeTreeInconsistent, int64(old), "the tree of size %d does not extend the checkpoint of size %d: %v", n, old, err) //nolint:gosec // G115
		}
	}
	return root, nil
}

// Verify re-verifies org's whole chain against its latest checkpoint: the
// note, the root of the stored tiles, every chain link from genesis and
// the root recomputed from the chain. A success is recorded as the org's
// last verification.
func (s *Service) Verify(ctx context.Context, org ids.OrgID) (Result, error) {
	origin := s.Origin(org)
	vs, err := s.verifiers(ctx, origin)
	if err != nil {
		return Result{}, err
	}
	var res Result
	var root merkle.Hash
	var size uint64
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		res = Result{}
		q := dbq.New(tx)
		if st, err := q.GetEvidenceIntegrity(ctx, org); err == nil && st.State != "OK" {
			res.Stopped = true
			return nil
		} else if err != nil && !db.IsNoRows(err) {
			return err
		}
		latest, err := q.LatestCheckpoint(ctx, org)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		if root, err = openStored(latest, origin, vs); err != nil {
			return err
		}
		size = uint64(latest.TreeSize) //nolint:gosec // G115: tree_size > 0
		tiled, err := merkle.Root(ctx, tiles{q: q, org: org}, size)
		if errors.Is(err, merkle.ErrTileNotFound) || (err == nil && !tiled.Equal(root)) {
			return integrity(CodeTreeMismatch, latest.TreeSize, "the tiles do not give the root of the checkpoint of size %d", size)
		}
		return err
	}, db.ReadOnly())
	if err == nil && !res.Stopped && size > 0 {
		err = s.verifyChain(ctx, org, size, root)
	}
	var ie *IntegrityError
	if errors.As(err, &ie) {
		return Result{Stopped: true}, s.report(ctx, org, CheckDaily, ie)
	}
	if err != nil {
		return Result{}, fmt.Errorf("checkpoints: verify org %s: %w", org, err)
	}
	if res.Stopped || size == 0 {
		return res, nil
	}
	res.Size = size
	return res, s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).MarkEvidenceVerified(ctx, org, int64(size)) //nolint:gosec // G115: size ≤ tree_size
		return err
	})
}

// poolTiles reads an org's tiles, one short read-only transaction each, for
// a check that runs beside another transaction.
type poolTiles struct {
	pool *db.Pool
	org  ids.OrgID
}

func (t poolTiles) ReadTile(ctx context.Context, id merkle.TileID) ([]byte, error) {
	var b []byte
	err := t.pool.InTenantTx(ctx, t.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		b, err = tiles{q: dbq.New(tx), org: t.org}.ReadTile(ctx, id)
		return err
	}, db.ReadOnly())
	return b, err
}

// verifyChain walks the chain from genesis and checks that its first size
// entries give root, and give exactly the stored tiles.
func (s *Service) verifyChain(ctx context.Context, org ids.OrgID, size uint64, root merkle.Hash) error {
	var b merkle.Builder
	tc := merkle.NewTileCheck(poolTiles{pool: s.Pool, org: org})
	_, err := ledger.VerifyEach(ctx, s.Pool, org, func(l domain.Link) error {
		if b.Size() >= size {
			return nil
		}
		h, err := merkle.HashFromBytes(l.EntryHash)
		if err != nil {
			return integrity(CodeChainLink, l.Seq, "seq %d has a malformed entry hash", l.Seq)
		}
		leaf := merkle.LeafHash(h[:])
		b.Add(leaf)
		return tileFailure(tc.Add(ctx, leaf), l.Seq)
	})
	if err == nil && b.Size() == size {
		err = tileFailure(tc.Finish(ctx), int64(size)) //nolint:gosec // G115
	}
	var ie *IntegrityError
	if errors.As(err, &ie) {
		return ie
	}
	if err != nil {
		return chainFailure(err)
	}
	if b.Size() < size {
		return integrity(CodeChainLink, int64(b.Size())+1, "the chain has %d entries, fewer than the checkpoint of size %d", b.Size(), size) //nolint:gosec // G115
	}
	if !b.Root().Equal(root) {
		return integrity(CodeTreeMismatch, int64(size), "the chain does not give the root of the checkpoint of size %d", size) //nolint:gosec // G115
	}
	return nil
}

func tileFailure(err error, seq int64) error {
	if errors.Is(err, merkle.ErrTileMismatch) || errors.Is(err, merkle.ErrTileNotFound) {
		return integrity(CodeTreeMismatch, seq, "%v", err)
	}
	return err
}

// report records an integrity failure: the org's integrity becomes FAILED,
// security.evidence_integrity_failed goes to its audit ledger and org and
// security admins are notified, in one transaction. A failure already
// recorded is not reported again. It returns ie unless reporting failed.
func (s *Service) report(ctx context.Context, org ids.OrgID, check string, ie *IntegrityError) error {
	s.log().ErrorContext(ctx, "security.evidence_integrity_failed", slog.String("org", org.String()),
		slog.String("check", check), slog.String("code", ie.Code), slog.Int64("seq", ie.Seq))
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		seq := pgtype.Int8{Int64: ie.Seq, Valid: ie.Seq > 0}
		n, err := q.MarkEvidenceIntegrityFailed(ctx, org, ie.Code, seq)
		if err != nil || n == 0 {
			return err
		}
		details := map[string]string{"check": check}
		if ie.Seq > 0 {
			details["seq"] = strconv.FormatInt(ie.Seq, 10)
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "security.evidence_integrity_failed", Actor: Actor, Outcome: audit.Failure, ReasonCode: ie.Code,
			Object: &audit.Object{Type: "evidence_log", ID: org.String()}, Details: details,
		}); err != nil {
			return err
		}
		if s.Notify == nil {
			return nil
		}
		_, err = s.Notify.Enqueue(ctx, tx, napp.Message{
			Org: org, Type: "security.evidence_integrity_failed", Params: map[string]string{"check": check, "reason": ie.Code},
		})
		return err
	})
	if err != nil {
		return fmt.Errorf("checkpoints: report integrity failure of org %s: %w", org, err)
	}
	return ie
}

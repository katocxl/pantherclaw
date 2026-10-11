// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the EvidenceService use cases (G0 M7 design decisions
// 8 and 13, HR-194, HR-196): the org's checkpoints and integrity status,
// inclusion and consistency proofs from the stored tiles, and verify
// bundles (pantherclaw.bundle/v1) that `pclaw verify` checks offline.
//
// Checkpoints and proofs commit to the whole org and carry only sizes and
// hashes, so evidence.read anywhere in the org reads them. A bundle of
// transactions needs evidence.read where each transaction's agent lives,
// like run.read; a bundle of a sequence range covers every entry of the
// org, audit events included, so it needs evidence.read and audit.read at
// org scope. Ids of another org are not found (T-037).
package app

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/jsontext"
	"errors"
	"maps"
	"slices"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/evidence/retention"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Limits of one export.
const (
	// MaxTransactions and MaxRange bound a bundle's selection.
	MaxTransactions = 50
	MaxRange        = 1000
	// MaxBundleBytes keeps a bundle within one API response.
	MaxBundleBytes = 3 << 20
)

// Errors.
var (
	ErrNoCheckpoint    = pcerr.New(pcerr.NotFound, "CHECKPOINT_NOT_FOUND", "no checkpoint of that size")
	ErrNotInCheckpoint = pcerr.New(pcerr.FailedPrecondition, "NOT_IN_CHECKPOINT", "that entry is not in that checkpoint")
	ErrEntryNotFound   = pcerr.New(pcerr.NotFound, "ENTRY_NOT_FOUND", "no chained entry at that position")
	ErrTxnNotFound     = pcerr.New(pcerr.NotFound, "TRANSACTION_NOT_FOUND", "transaction not found")
	ErrBadSelection    = pcerr.New(pcerr.InvalidArgument, "INVALID_SELECTION", "select 1 to 50 transactions or a range of 1 to 1,000 entries")
	ErrBadConsistency  = pcerr.New(pcerr.InvalidArgument, "INVALID_CONSISTENCY", "the earlier tree size must be at most the later checkpoint's")
	ErrBundleTooLarge  = pcerr.New(pcerr.ResourceExhausted, "BUNDLE_TOO_LARGE", "the bundle is too large: select fewer transactions or a shorter range")
	ErrNothingToExport = pcerr.New(pcerr.NotFound, "NO_CHAINED_ENTRIES", "nothing chained to export yet")
)

// Service serves the evidence use cases.
type Service struct {
	pool      *db.Pool
	logOrigin string
	// replay and its per-caller limit; nil until WithReplay.
	replay      Replayer
	replayLimit *httpx.Limiter
	// Evidence packs; nil until WithPacks.
	enqueuePack PackEnqueuer
	editions    Editions
}

// New returns the service; logOrigin is evidence.log_origin.
func New(pool *db.Pool, logOrigin string) *Service { return &Service{pool: pool, logOrigin: logOrigin} }

// Origin returns the checkpoint origin of org (PAP-1 §9.4).
func (s *Service) Origin(org ids.OrgID) string { return s.logOrigin + "/org/" + org.String() }

// Checkpoint is one stored checkpoint.
type Checkpoint struct {
	Size    uint64
	Root    []byte
	Note    []byte
	KID     string
	PQKID   string
	Created time.Time
}

func checkpointOf(size int64, root, note []byte, kid string, pq *string, created time.Time) Checkpoint {
	c := Checkpoint{Size: uint64(size), Root: root, Note: note, KID: kid, Created: created} //nolint:gosec // G115: tree_size > 0
	if pq != nil {
		c.PQKID = *pq
	}
	return c
}

// Integrity is the org's integrity status.
type Integrity struct {
	Failed       bool
	Code         string
	Seq          int64
	FailedAt     time.Time
	VerifiedSize uint64
	VerifiedAt   time.Time
	// The org's newest anchor (HR-195: anchoring failures are visible in
	// the integrity status); AnchorState is empty when there is none.
	AnchorState  string
	AnchorPeriod time.Time
	AnchorError  string
}

// CheckpointPage is one page of checkpoints, newest first.
type CheckpointPage struct {
	Items     []Checkpoint
	Next      string
	Origin    string
	Integrity Integrity
}

func reader(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.CanAnywhere(td.PermEvidenceRead) {
		return c, td.ErrPermissionDenied(td.PermEvidenceRead)
	}
	return c, nil
}

// pageToken encodes the tree size to continue below.
func pageToken(size uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], size)
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func parsePageToken(tok string) (int64, error) {
	if tok == "" {
		return 0, nil
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(tok)
	if err != nil || len(b) != 8 {
		return 0, page.ErrBadToken
	}
	v := binary.BigEndian.Uint64(b)
	if v < 2 || v > 1<<62 {
		return 0, page.ErrBadToken
	}
	return int64(v), nil
}

// ListCheckpoints lists the org's checkpoints, newest first.
func (s *Service) ListCheckpoints(ctx context.Context, size int32, token string) (CheckpointPage, error) {
	c, err := reader(ctx)
	if err != nil {
		return CheckpointPage{}, err
	}
	before, err := parsePageToken(token)
	if err != nil {
		return CheckpointPage{}, err
	}
	limit := page.Default
	if size > 0 {
		limit = int(min(size, page.Max))
	}
	out := CheckpointPage{Origin: s.Origin(c.Org)}
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListCheckpointsPage(ctx, c.Org, before, int32(limit+1)) //nolint:gosec // G115: ≤ 201
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			out.Next = pageToken(uint64(rows[limit-1].TreeSize)) //nolint:gosec // G115: tree_size > 0
		}
		for _, r := range rows {
			out.Items = append(out.Items, checkpointOf(r.TreeSize, r.RootHash, r.Note, r.Kid, r.PqKid, r.CreatedAt))
		}
		newest, err := q.ListOrgAnchorsPage(ctx, c.Org, nil, 1)
		if err != nil {
			return err
		}
		if len(newest) == 1 {
			a := newest[0]
			out.Integrity.AnchorState, out.Integrity.AnchorPeriod = a.State, a.Period
			if a.ErrorCode != nil {
				out.Integrity.AnchorError = *a.ErrorCode
			}
		}
		st, err := q.GetEvidenceIntegrity(ctx, c.Org)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		out.Integrity.Failed, out.Integrity.Seq = st.State != "OK", st.FailedSeq.Int64
		if st.FailureCode != nil {
			out.Integrity.Code = *st.FailureCode
		}
		if st.FailedAt != nil {
			out.Integrity.FailedAt = *st.FailedAt
		}
		if st.VerifiedAt != nil {
			out.Integrity.VerifiedAt, out.Integrity.VerifiedSize = *st.VerifiedAt, uint64(st.VerifiedSize.Int64) //nolint:gosec // G115: > 0
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// checkpointAt returns the checkpoint of size, or the latest for 0.
func checkpointAt(ctx context.Context, q *dbq.Queries, org ids.OrgID, size uint64) (Checkpoint, error) {
	if size == 0 {
		r, err := q.LatestCheckpoint(ctx, org)
		if db.IsNoRows(err) {
			return Checkpoint{}, ErrNoCheckpoint
		} else if err != nil {
			return Checkpoint{}, err
		}
		return checkpointOf(r.TreeSize, r.RootHash, r.Note, r.Kid, r.PqKid, r.CreatedAt), nil
	}
	if size > 1<<62 {
		return Checkpoint{}, ErrNoCheckpoint
	}
	r, err := q.GetCheckpointBySize(ctx, org, int64(size))
	if db.IsNoRows(err) {
		return Checkpoint{}, ErrNoCheckpoint
	} else if err != nil {
		return Checkpoint{}, err
	}
	return checkpointOf(r.TreeSize, r.RootHash, r.Note, r.Kid, r.PqKid, r.CreatedAt), nil
}

// GetCheckpoint returns the checkpoint of size, or the latest for 0.
func (s *Service) GetCheckpoint(ctx context.Context, size uint64) (Checkpoint, string, error) {
	c, err := reader(ctx)
	if err != nil {
		return Checkpoint{}, "", err
	}
	var out Checkpoint
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = checkpointAt(ctx, dbq.New(tx), c.Org, size)
		return err
	}, db.ReadOnly())
	return out, s.Origin(c.Org), err
}

// InclusionProof proves an entry is in a checkpoint.
type InclusionProof struct {
	Seq       int64
	Size      uint64
	EntryHash []byte
	Proof     [][]byte
}

func hashes(hs []merkle.Hash) [][]byte {
	out := make([][]byte, len(hs))
	for i := range hs {
		out[i] = hs[i][:]
	}
	return out
}

// GetInclusionProof proves the entry at seq is in the checkpoint of size
// (the latest for 0).
func (s *Service) GetInclusionProof(ctx context.Context, seq int64, size uint64) (InclusionProof, error) {
	c, err := reader(ctx)
	if err != nil {
		return InclusionProof{}, err
	}
	var out InclusionProof
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		cp, err := checkpointAt(ctx, q, c.Org, size)
		if err != nil {
			return err
		}
		if seq < 1 || uint64(seq) > cp.Size {
			return ErrNotInCheckpoint
		}
		h, err := q.LedgerEntryHashAt(ctx, c.Org, seq)
		if db.IsNoRows(err) {
			return ErrEntryNotFound
		} else if err != nil {
			return err
		}
		proof, err := merkle.InclusionProof(ctx, tiles{q: q, org: c.Org}, uint64(seq-1), cp.Size)
		if err != nil {
			return err
		}
		out = InclusionProof{Seq: seq, Size: cp.Size, EntryHash: h, Proof: hashes(proof)}
		return nil
	}, db.ReadOnly(), db.RepeatableRead())
	return out, err
}

// ConsistencyProof proves the tree of size To extends the tree of size From.
type ConsistencyProof struct {
	From, To uint64
	Proof    [][]byte
}

// GetConsistencyProof proves the checkpoint of size to (the latest for 0)
// extends the tree of size from.
func (s *Service) GetConsistencyProof(ctx context.Context, from, to uint64) (ConsistencyProof, error) {
	c, err := reader(ctx)
	if err != nil {
		return ConsistencyProof{}, err
	}
	var out ConsistencyProof
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		cp, err := checkpointAt(ctx, q, c.Org, to)
		if err != nil {
			return err
		}
		if from < 1 || from > cp.Size {
			return ErrBadConsistency
		}
		out = ConsistencyProof{From: from, To: cp.Size}
		if from == cp.Size {
			return nil
		}
		proof, err := merkle.ConsistencyProof(ctx, tiles{q: q, org: c.Org}, from, cp.Size)
		out.Proof = hashes(proof)
		return err
	}, db.ReadOnly(), db.RepeatableRead())
	return out, err
}

// tiles reads stored tiles in a transaction (merkle.TileReader).
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

// Selection is what a bundle holds: transactions, or the entries From..To.
type Selection struct {
	Transactions []ids.UUID
	From, To     int64
}

// Export is a built bundle.
type Export struct {
	Bundle         []byte
	Entries        int
	Receipts       int
	CheckpointSize uint64
	// Anchored: the bundle holds the anchor of one of its checkpoints.
	Anchored bool
}

// chained is a chained entry as both entry queries return it.
type chained struct {
	seq                 int64
	prevHash, entryHash []byte
	id                  ids.UUID
	kind, actorType     string
	actorID             string
	occurredAt          time.Time
	body                []byte
	removedAt           *time.Time
	policy              *ids.UUID
}

func (e chained) bundleEntry(labels map[ids.UUID]string) bundle.Entry {
	out := bundle.Entry{
		Seq: e.seq, ID: e.id.String(), Kind: e.kind, Actor: domain.Actor{Type: e.actorType, ID: e.actorID},
		TS: domain.Timestamp(e.occurredAt), PrevHash: e.prevHash, EntryHash: e.entryHash,
	}
	if e.removedAt != nil {
		r := &bundle.Removal{At: e.removedAt.UTC().Format(time.RFC3339)}
		if e.policy != nil {
			r.Policy = e.policy.String()
			if l, ok := labels[*e.policy]; ok {
				r.Policy = l
			}
		}
		out.Removed = r
	} else {
		out.Body = jsontext.Value(e.body)
	}
	return out
}

// ExportBundle builds a bundle of sel: the receipts, their chained ledger
// entries, the latest checkpoint and an inclusion proof to it for every
// entry it covers, and, when consistencyFrom is set, the proof that the
// latest checkpoint extends the tree of that size (with that checkpoint).
// When one of the org's checkpoints is anchored, the newest anchor goes in
// too: the org's leaf and nonce, the anchor's leaves, signed statement,
// Rekor entry and timestamp, with the anchored checkpoint and the proof
// that the latest one extends it. Entries not chained yet are left out;
// entries the latest checkpoint does not cover yet have no proof, which
// `pclaw verify` reports as not available, as it reports a missing anchor.
func (s *Service) ExportBundle(ctx context.Context, sel Selection, consistencyFrom uint64) (Export, error) {
	c, err := reader(ctx)
	if err != nil {
		return Export{}, err
	}
	byTxn := len(sel.Transactions) > 0
	switch {
	case byTxn && (len(sel.Transactions) > MaxTransactions || sel.From != 0 || sel.To != 0):
		return Export{}, ErrBadSelection
	case !byTxn && (sel.From < 1 || sel.To < sel.From || sel.To-sel.From >= MaxRange):
		return Export{}, ErrBadSelection
	case !byTxn:
		org := td.OrgPath(c.Org)
		if err := c.Require(td.PermEvidenceRead, org); err != nil {
			return Export{}, err
		}
		if err := c.Require(td.PermAuditRead, org); err != nil {
			return Export{}, err
		}
	}
	b := &bundle.Bundle{Format: bundle.Format, Org: c.Org.String(), Origin: s.Origin(c.Org)}
	var out Export
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var entries []chained
		var err error
		if byTxn {
			entries, b.Receipts, err = s.transactions(ctx, c, q, sel.Transactions)
		} else {
			entries, b.Receipts, err = s.entryRange(ctx, c.Org, q, sel.From, sel.To)
		}
		if err != nil {
			return err
		}
		if len(entries) == 0 && len(b.Receipts) == 0 {
			return ErrNothingToExport
		}
		labels, err := policyLabels(ctx, q, c.Org, entries)
		if err != nil {
			return err
		}
		for _, e := range entries {
			b.Entries = append(b.Entries, e.bundleEntry(labels))
		}
		latest, err := checkpointAt(ctx, q, c.Org, 0)
		if errors.Is(err, ErrNoCheckpoint) {
			if consistencyFrom > 0 {
				return ErrBadConsistency
			}
			return nil
		} else if err != nil {
			return err
		}
		if consistencyFrom > latest.Size {
			return ErrBadConsistency
		}
		out.CheckpointSize = latest.Size
		notes := map[uint64][]byte{latest.Size: latest.Note}
		t := tiles{q: q, org: c.Org}
		for _, e := range entries {
			seq := uint64(e.seq) //nolint:gosec // G115: seq > 0
			if seq > latest.Size {
				continue
			}
			proof, err := merkle.InclusionProof(ctx, t, seq-1, latest.Size)
			if err != nil {
				return err
			}
			b.Inclusion = append(b.Inclusion, bundle.Inclusion{Seq: e.seq, Size: latest.Size, Proof: hashes(proof)})
		}
		if consistencyFrom > 0 && consistencyFrom < latest.Size {
			if earlier, err := checkpointAt(ctx, q, c.Org, consistencyFrom); err == nil {
				notes[consistencyFrom] = earlier.Note
			} else if !errors.Is(err, ErrNoCheckpoint) {
				return err
			}
		}
		// When anchored, the org's leaf in its newest anchor, with the
		// checkpoint it commits to (HR-195, design decision 13).
		an, err := latestAnchor(ctx, q, c.Org, latest.Size)
		if err != nil {
			return err
		}
		if an != nil {
			notes[an.anchor.Checkpoint] = an.note
			b.Anchor, out.Anchored = an.anchor, true
		}
		sizes := slices.Sorted(maps.Keys(notes))
		for _, size := range sizes {
			b.Checkpoints = append(b.Checkpoints, string(notes[size]))
		}
		// Every checkpoint extends the one before it, and the latest extends
		// the tree the requester saved (pclaw verify --previous).
		pairs := [][2]uint64{}
		for i := 1; i < len(sizes); i++ {
			pairs = append(pairs, [2]uint64{sizes[i-1], sizes[i]})
		}
		if consistencyFrom > 0 && consistencyFrom < latest.Size && !slices.Contains(pairs, [2]uint64{consistencyFrom, latest.Size}) {
			pairs = append(pairs, [2]uint64{consistencyFrom, latest.Size})
		}
		for _, p := range pairs {
			proof, err := merkle.ConsistencyProof(ctx, t, p[0], p[1])
			if err != nil {
				return err
			}
			b.Consistency = append(b.Consistency, bundle.Consistency{From: p[0], To: p[1], Proof: hashes(proof)})
		}
		return nil
	}, db.ReadOnly(), db.RepeatableRead())
	if err != nil {
		return Export{}, err
	}
	raw, err := bundle.Encode(b)
	if err != nil {
		return Export{}, pcerr.Wrap(err, pcerr.Internal, "BUNDLE_INVALID", "internal error")
	}
	if len(raw) > MaxBundleBytes {
		return Export{}, ErrBundleTooLarge
	}
	out.Bundle, out.Entries, out.Receipts = raw, len(b.Entries), len(b.Receipts)
	return out, nil
}

// transactions collects the receipts of txns, after checking evidence.read
// where each one's agent lives, and their chained entries.
func (s *Service) transactions(ctx context.Context, c tenancy.Caller, q *dbq.Queries, txns []ids.UUID) ([]chained, []string, error) {
	var receipts []string
	var entryIDs []ids.UUID
	seen := map[ids.UUID]bool{}
	for _, id := range txns {
		if seen[id] {
			continue
		}
		seen[id] = true
		agentID, err := q.TransactionAgent(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return nil, nil, ErrTxnNotFound
		} else if err != nil {
			return nil, nil, err
		}
		a, err := q.GetAgent(ctx, c.Org, agentID)
		if err != nil {
			return nil, nil, err
		}
		path, err := agents.PathOf(ctx, q, a)
		if err != nil {
			return nil, nil, err
		}
		if err := c.Require(td.PermEvidenceRead, path); err != nil {
			return nil, nil, err
		}
		rows, err := q.TransactionReceipts(ctx, c.Org, id)
		if err != nil {
			return nil, nil, err
		}
		for _, r := range rows {
			if r.BodyRemovedAt == nil {
				receipts = append(receipts, r.ReceiptJws)
			}
			entryIDs = append(entryIDs, r.LedgerEntryID)
		}
	}
	rows, err := q.ChainedEntriesByID(ctx, c.Org, entryIDs)
	if err != nil {
		return nil, nil, err
	}
	entries := make([]chained, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, chained{
			seq: r.Seq, prevHash: r.PrevHash, entryHash: r.EntryHash, id: r.ID, kind: r.Kind, actorType: r.ActorType,
			actorID: r.ActorID, occurredAt: r.OccurredAt, body: r.Body, removedAt: r.BodyRemovedAt, policy: r.RemovedByPolicy,
		})
	}
	return entries, receipts, nil
}

// policyLabels names the retention revisions that removed entries' bodies,
// for example "receipts r2" (HR-198), so `pclaw verify` reports under which
// policy and when a body was removed.
func policyLabels(ctx context.Context, q *dbq.Queries, org ids.OrgID, entries []chained) (map[ids.UUID]string, error) {
	var policies []ids.UUID
	for _, e := range entries {
		if e.policy != nil {
			policies = append(policies, *e.policy)
		}
	}
	if len(policies) == 0 {
		return nil, nil
	}
	rows, err := q.RetentionPolicyLabels(ctx, org, policies)
	if err != nil {
		return nil, err
	}
	out := make(map[ids.UUID]string, len(rows))
	for _, r := range rows {
		out[r.ID] = retention.Label(retention.Category(r.Category), int(r.Revision))
	}
	return out, nil
}

// entryRange collects the chained entries from..to and the receipts they
// record.
func (s *Service) entryRange(ctx context.Context, org ids.OrgID, q *dbq.Queries, from, to int64) ([]chained, []string, error) {
	rows, err := q.ChainedLedgerRange(ctx, dbq.ChainedLedgerRangeParams{OrgID: org, AfterSeq: from - 1, UptoSeq: to, MaxRows: MaxRange})
	if err != nil {
		return nil, nil, err
	}
	entries := make([]chained, 0, len(rows))
	entryIDs := make([]ids.UUID, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, chained{
			seq: r.Seq, prevHash: r.PrevHash, entryHash: r.EntryHash, id: r.ID, kind: r.Kind, actorType: r.ActorType,
			actorID: r.ActorID, occurredAt: r.OccurredAt, body: r.Body, removedAt: r.BodyRemovedAt, policy: r.RemovedByPolicy,
		})
		entryIDs = append(entryIDs, r.ID)
	}
	recs, err := q.ReceiptsOfEntries(ctx, org, entryIDs)
	if err != nil {
		return nil, nil, err
	}
	var receipts []string
	for _, r := range recs {
		if r.BodyRemovedAt == nil {
			receipts = append(receipts, r.ReceiptJws)
		}
	}
	return entries, receipts, nil
}

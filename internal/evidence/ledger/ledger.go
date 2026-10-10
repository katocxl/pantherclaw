// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ledger stores evidence entries and chains them (ADR-0009, HR-110).
//
// Append writes an unchained entry inside the caller's business transaction:
// no hot row is touched on the authorization path. ChainOrg, run by the
// per-org chainer job, links every committed entry whose transaction id is
// below pg_snapshot_xmin, in (xid, id) order, so entries from rolled-back
// transactions never leave gaps and entries from still-running transactions
// wait for the next run. Verify recomputes the whole chain.
package ledger

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Append inserts an unchained entry for tx's org. body must be a canonical
// JSON object (see domain.CanonicalBody).
func Append(ctx context.Context, tx db.TenantTx, kind string, actor domain.Actor, body []byte) (domain.Entry, error) {
	e := domain.Entry{Org: tx.OrgID(), ID: ids.NewV7(), Kind: kind, Actor: actor, Body: body}
	if err := e.Validate(); err != nil {
		return domain.Entry{}, err
	}
	at, err := dbq.New(tx).InsertLedgerEntry(ctx, dbq.InsertLedgerEntryParams{
		OrgID: e.Org, ID: e.ID, Kind: e.Kind, ActorType: actor.Type, ActorID: actor.ID, Body: e.Body,
	})
	if err != nil {
		return domain.Entry{}, fmt.Errorf("ledger: append %s: %w", kind, err)
	}
	e.OccurredAt = at
	return e, nil
}

// ChainOrg links up to batch pending entries of org and returns how many it
// linked. It holds the org's head row lock for the duration, so chainers for
// one org never interleave.
func ChainOrg(ctx context.Context, pool *db.Pool, org ids.OrgID, batch int) (int, error) {
	if batch < 1 || batch > 10000 {
		return 0, fmt.Errorf("ledger: batch must be 1..10000")
	}
	var n int
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.EnsureLedgerHead(ctx, org); err != nil {
			return err
		}
		head, err := q.LockLedgerHead(ctx, org)
		if err != nil {
			return err
		}
		xmin, err := q.CurrentXmin(ctx)
		if err != nil {
			return err
		}
		rows, err := q.UnchainedLedgerEntries(ctx, dbq.UnchainedLedgerEntriesParams{
			OrgID: org, Watermark: head.XidWatermark, Xmin: xmin, MaxRows: int32(batch), //nolint:gosec // G115: batch ≤ 10000
		})
		if err != nil {
			return err
		}
		seq, hash := head.Seq, head.HeadHash
		for _, r := range rows {
			e := domain.Entry{
				Org: org, ID: r.ID, Kind: r.Kind,
				Actor: domain.Actor{Type: r.ActorType, ID: r.ActorID}, OccurredAt: r.OccurredAt, Body: r.Body,
			}
			link, err := domain.Next(seq, hash, e)
			if err != nil {
				return fmt.Errorf("ledger: entry %s: %w", r.ID, err)
			}
			if err := q.InsertLedgerLink(ctx, dbq.InsertLedgerLinkParams{
				OrgID: org, Seq: link.Seq, EntryID: link.EntryID, PrevHash: link.PrevHash, EntryHash: link.EntryHash,
			}); err != nil {
				return err
			}
			seq, hash = link.Seq, link.EntryHash
		}
		// When the batch was not full, every committed entry below xmin is
		// now chained, so the watermark can move up to xmin.
		watermark := head.XidWatermark
		if len(rows) < batch {
			watermark = xmin
		}
		n = len(rows)
		return q.UpdateLedgerHead(ctx, dbq.UpdateLedgerHeadParams{OrgID: org, Seq: seq, HeadHash: hash, Watermark: watermark})
	})
	if err != nil {
		return 0, fmt.Errorf("ledger: chain org %s: %w", org, err)
	}
	return n, nil
}

// ChainAll runs ChainOrg until no full batch remains.
func ChainAll(ctx context.Context, pool *db.Pool, org ids.OrgID, batch int) (int, error) {
	total := 0
	for {
		n, err := ChainOrg(ctx, pool, org, batch)
		total += n
		if err != nil || n < batch {
			return total, err
		}
	}
}

// Head is the verified state of an org chain.
type Head struct {
	Seq  int64
	Hash []byte
}

// Verify recomputes the org's chain from genesis and checks it against the
// stored head. It returns domain.ErrChainBroken on any mismatch.
func Verify(ctx context.Context, pool *db.Pool, org ids.OrgID) (Head, error) {
	return VerifyEach(ctx, pool, org, nil)
}

// VerifyEach is Verify, calling visit with each link once it verified, in
// seq order. It reads the whole chain in one snapshot, so a chainer running
// meanwhile changes nothing it sees. An entry whose body retention removed
// is checked by its position and prev_hash, and continues the chain by its
// stored hash.
func VerifyEach(ctx context.Context, pool *db.Pool, org ids.OrgID, visit func(domain.Link) error) (Head, error) {
	v := domain.NewVerifier()
	var stored dbq.GetLedgerHeadRow
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		stored, err = q.GetLedgerHead(ctx, org)
		if errors.Is(err, pgx.ErrNoRows) {
			stored = dbq.GetLedgerHeadRow{HeadHash: domain.GenesisHash}
		} else if err != nil {
			return err
		}
		var after int64
		for {
			page, err := q.ChainedLedgerEntries(ctx, org, after, 1000)
			if err != nil {
				return err
			}
			for _, r := range page {
				link := domain.Link{Seq: r.Seq, EntryID: r.ID, PrevHash: r.PrevHash, EntryHash: r.EntryHash}
				if r.BodyRemovedAt != nil {
					err = v.AddRemoved(link)
				} else {
					err = v.Add(link, domain.Entry{
						Org: org, ID: r.ID, Kind: r.Kind,
						Actor: domain.Actor{Type: r.ActorType, ID: r.ActorID}, OccurredAt: r.OccurredAt, Body: r.Body,
					})
				}
				if err != nil {
					return err
				}
				if visit != nil {
					if err := visit(link); err != nil {
						return err
					}
				}
				after = r.Seq
			}
			if len(page) < 1000 {
				return nil
			}
		}
	}, db.ReadOnly(), db.RepeatableRead())
	if err != nil {
		return Head{}, fmt.Errorf("ledger: verify org %s: %w", org, err)
	}
	seq, hash := v.Head()
	if seq != stored.Seq || !bytes.Equal(hash, stored.HeadHash) {
		return Head{}, fmt.Errorf("ledger: verify org %s: %w: stored head (seq %d) differs from recomputed head (seq %d)",
			org, domain.ErrChainBroken, stored.Seq, seq)
	}
	return Head{Seq: seq, Hash: hash}, nil
}

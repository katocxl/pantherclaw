// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/jsontext"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

// Anchors (G0 M7 design decision 12, HR-195). An org sees the anchors that
// hold one of its checkpoints: its own leaf position and checkpoint, the
// global root and the anchor's state. Like checkpoints, they carry only
// sizes and hashes, so evidence.read anywhere in the org reads them.

// Anchor is one anchor as it concerns the org.
type Anchor struct {
	ID             ids.UUID
	Period         time.Time
	State          string
	CheckpointSize uint64
	LeafIndex      uint32
	Leaves         uint32
	Root           []byte
	KID            string
	Attempts       int32
	ErrorCode      string
	Created        time.Time
	Anchored       time.Time
}

// AnchorPage is one page of anchors, newest period first.
type AnchorPage struct {
	Items []Anchor
	Next  string
}

func anchorToken(period time.Time) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(period.UnixMicro()))
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func parseAnchorToken(tok string) (*time.Time, error) {
	if tok == "" {
		return nil, nil //nolint:nilnil // no token: from the newest
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(tok)
	if err != nil || len(b) != 8 {
		return nil, page.ErrBadToken
	}
	v := binary.BigEndian.Uint64(b)
	if v == 0 || v > 1<<62 {
		return nil, page.ErrBadToken
	}
	t := time.UnixMicro(int64(v)).UTC()
	return &t, nil
}

// ListAnchors lists the anchors holding one of the org's checkpoints.
func (s *Service) ListAnchors(ctx context.Context, size int32, token string) (AnchorPage, error) {
	c, err := reader(ctx)
	if err != nil {
		return AnchorPage{}, err
	}
	before, err := parseAnchorToken(token)
	if err != nil {
		return AnchorPage{}, err
	}
	limit := page.Default
	if size > 0 {
		limit = int(min(size, page.Max))
	}
	var out AnchorPage
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListOrgAnchorsPage(ctx, c.Org, before, int32(limit+1)) //nolint:gosec // G115: ≤ 201
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			out.Next = anchorToken(rows[limit-1].Period)
		}
		for _, r := range rows {
			a := Anchor{
				ID: r.ID, Period: r.Period, State: r.State, CheckpointSize: uint64(r.CheckpointSize), //nolint:gosec // G115: > 0
				LeafIndex: uint32(r.LeafIndex), Leaves: uint32(r.LeafCount), Root: r.Root, KID: r.Kid, //nolint:gosec // G115: < 2^20
				Attempts: r.Attempts, Created: r.CreatedAt,
			}
			if r.ErrorCode != nil {
				a.ErrorCode = *r.ErrorCode
			}
			if r.AnchoredAt != nil {
				a.Anchored = *r.AnchoredAt
			}
			out.Items = append(out.Items, a)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// anchored is the org's newest anchored leaf whose checkpoint a bundle can
// prove: what bundle.Anchor holds, and the checkpoint's note.
type anchored struct {
	anchor *bundle.Anchor
	note   []byte
}

// latestAnchor returns the org's newest anchor of a checkpoint of at most
// size maxSize, or nil when none is anchored yet.
func latestAnchor(ctx context.Context, q *dbq.Queries, org ids.OrgID, maxSize uint64) (*anchored, error) {
	r, err := q.LatestOrgAnchor(ctx, org, int64(maxSize)) //nolint:gosec // G115: tree sizes < 2^62
	if db.IsNoRows(err) {
		return nil, nil //nolint:nilnil // not anchored yet
	} else if err != nil {
		return nil, err
	}
	if len(r.Leaves) == 0 || len(r.Leaves)%merkle.HashSize != 0 || len(r.Leaves)/merkle.HashSize > anchor.MaxLeaves {
		return nil, nil //nolint:nilnil // a malformed anchor is left out, never exported
	}
	leaves := make([][]byte, 0, len(r.Leaves)/merkle.HashSize)
	for i := 0; i < len(r.Leaves); i += merkle.HashSize {
		leaves = append(leaves, r.Leaves[i:i+merkle.HashSize])
	}
	return &anchored{note: r.Note, anchor: &bundle.Anchor{
		Checkpoint: uint64(r.CheckpointSize), Nonce: r.Nonce, Leaves: leaves, //nolint:gosec // G115: > 0
		Statement: r.Statement, Signature: r.Signature, RekorEntry: jsontext.Value(r.RekorEntry), Timestamp: r.TimestampToken,
	}}, nil
}

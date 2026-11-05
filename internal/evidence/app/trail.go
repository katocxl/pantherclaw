// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/hex"
	"encoding/json/jsontext"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/globallog"
	"github.com/katocxl/pantherclaw/internal/evidence/merkle"
	"github.com/katocxl/pantherclaw/internal/evidence/receiptsig"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// globalProof returns the root log's newest checkpoint with its witnesses'
// cosignatures and the inclusion proof of the anchor's global root, or nil
// while the anchor is not in a checkpoint yet (G0 M35 D1041). The root log
// holds no tenant data, so it is read in the org's own transaction.
func globalProof(ctx context.Context, q *dbq.Queries, anchorID ids.UUID) (*bundle.GlobalLog, error) {
	leaf, err := q.GlobalLogLeafOfAnchor(ctx, anchorID)
	if db.IsNoRows(err) {
		return nil, nil //nolint:nilnil // not in the root log yet
	} else if err != nil {
		return nil, err
	}
	p, ok, err := globallog.Latest(ctx, q)
	if err != nil || !ok {
		return nil, err
	}
	index := uint64(leaf.LeafIndex) //nolint:gosec // G115: ≥ 0
	if index >= p.Size {
		return nil, nil //nolint:nilnil // a leaf the newest checkpoint does not cover yet
	}
	proof, err := merkle.InclusionProof(ctx, globallog.Tiles{Q: q}, index, p.Size)
	if err != nil {
		return nil, err
	}
	return &bundle.GlobalLog{Checkpoint: string(p.Note), Index: index, Proof: hashes(proof)}, nil
}

// receiptSigs returns the stored sigs[] of the receipts (G0 M35 D1042).
func receiptSigs(ctx context.Context, q *dbq.Queries, org ids.OrgID, receipts []string) ([]bundle.ReceiptSigs, error) {
	if len(receipts) == 0 {
		return nil, nil
	}
	digests := make([][]byte, len(receipts))
	for i, r := range receipts {
		digests[i] = receiptsig.Digest(r)
	}
	rows, err := q.ReceiptSignatures(ctx, org, digests)
	if err != nil {
		return nil, err
	}
	out := make([]bundle.ReceiptSigs, 0, len(rows))
	for _, r := range rows {
		out = append(out, bundle.ReceiptSigs{Receipt: hex.EncodeToString(r.ReceiptSha256), Sigs: jsontext.Value(r.Sigs)})
	}
	return out, nil
}

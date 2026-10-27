// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package capture

import (
	"context"
	"errors"

	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// PackSource opens the payload captures of a transaction for an evidence
// pack (G0 M7 decision 15, HR-199). Each capture goes through ReadCapture,
// as the pack's creator, so each is audited exactly as a person's read is
// (evidence.payload_read, with the pack named as the reason) and committed
// before its content is opened. A capture that was never kept is left out
// without a read.
type PackSource struct {
	Service *Service
}

// PackReason is the reason recorded for a capture read into pack id.
func PackReason(id ids.UUID) string { return "evidence pack " + id.String() }

// Captures returns the opened captures of txn as captures/<txn>/request.bin
// and captures/<txn>/response.bin, read as the creator in ctx for pack.
func (p PackSource) Captures(ctx context.Context, org ids.OrgID, packID, txn ids.UUID) ([]pack.File, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if c.Org != org {
		return nil, pcerr.New(pcerr.PermissionDenied, "ORG_MISMATCH", "the pack's creator is not of its org")
	}
	var out []pack.File
	for _, dir := range []Direction{Request, Response} {
		r, err := p.Service.ReadCapture(ctx, txn, dir, PackReason(packID))
		if errors.Is(err, ErrCaptureNotFound) {
			continue
		} else if err != nil {
			return nil, err
		}
		out = append(out, pack.File{Path: "captures/" + txn.String() + "/" + string(dir) + ".bin", Kind: pack.KindCapture, Data: r.Content})
	}
	return out, nil
}

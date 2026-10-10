// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package evidencerpc serves EvidenceService over Connect (G0 M7 track B).
// Handlers only translate: authentication, the coarse permission check and
// protovalidate have run before a handler is called, and the use cases
// check scopes.
package evidencerpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Evidence serves EvidenceService.
type Evidence struct {
	pantherclawv1connect.UnimplementedEvidenceServiceHandler
	svc *evapp.Service
}

// New returns the EvidenceService handler.
func New(svc *evapp.Service) *Evidence { return &Evidence{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func checkpointProto(c evapp.Checkpoint) *pantherclawv1.Checkpoint {
	return &pantherclawv1.Checkpoint{
		TreeSize: c.Size, RootHash: c.Root, Note: c.Note, Kid: c.KID, PqKid: c.PQKID, CreateTime: ts(c.Created),
	}
}

// ListCheckpoints implements EvidenceServiceHandler.
func (e *Evidence) ListCheckpoints(ctx context.Context, req *pantherclawv1.ListCheckpointsRequest) (*pantherclawv1.ListCheckpointsResponse, error) {
	p, err := e.svc.ListCheckpoints(ctx, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListCheckpointsResponse{NextPageToken: p.Next, Origin: p.Origin, Integrity: &pantherclawv1.LedgerIntegrity{
		State: pantherclawv1.LedgerIntegrityState_LEDGER_INTEGRITY_STATE_OK, VerifiedSize: p.Integrity.VerifiedSize, VerifyTime: ts(p.Integrity.VerifiedAt),
	}}
	if p.Integrity.Failed {
		out.Integrity.State = pantherclawv1.LedgerIntegrityState_LEDGER_INTEGRITY_STATE_FAILED
		out.Integrity.FailureCode, out.Integrity.FailedSeq, out.Integrity.FailTime = p.Integrity.Code, p.Integrity.Seq, ts(p.Integrity.FailedAt)
	}
	for _, c := range p.Items {
		out.Checkpoints = append(out.Checkpoints, checkpointProto(c))
	}
	return out, nil
}

// GetCheckpoint implements EvidenceServiceHandler.
func (e *Evidence) GetCheckpoint(ctx context.Context, req *pantherclawv1.GetCheckpointRequest) (*pantherclawv1.GetCheckpointResponse, error) {
	c, origin, err := e.svc.GetCheckpoint(ctx, req.GetTreeSize())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetCheckpointResponse{Checkpoint: checkpointProto(c), Origin: origin}, nil
}

// GetInclusionProof implements EvidenceServiceHandler.
func (e *Evidence) GetInclusionProof(ctx context.Context, req *pantherclawv1.GetInclusionProofRequest) (*pantherclawv1.GetInclusionProofResponse, error) {
	p, err := e.svc.GetInclusionProof(ctx, req.GetSeq(), req.GetTreeSize())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetInclusionProofResponse{Seq: p.Seq, TreeSize: p.Size, EntryHash: p.EntryHash, Proof: p.Proof}, nil
}

// GetConsistencyProof implements EvidenceServiceHandler.
func (e *Evidence) GetConsistencyProof(ctx context.Context, req *pantherclawv1.GetConsistencyProofRequest) (*pantherclawv1.GetConsistencyProofResponse, error) {
	p, err := e.svc.GetConsistencyProof(ctx, req.GetFromSize(), req.GetToSize())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetConsistencyProofResponse{FromSize: p.From, ToSize: p.To, Proof: p.Proof}, nil
}

// ExportBundle implements EvidenceServiceHandler.
func (e *Evidence) ExportBundle(ctx context.Context, req *pantherclawv1.ExportBundleRequest) (*pantherclawv1.ExportBundleResponse, error) {
	var sel evapp.Selection
	if r := req.GetRange(); r != nil {
		sel.From, sel.To = r.GetFromSeq(), r.GetToSeq()
	}
	for _, s := range req.GetTransactions().GetIds() {
		id, err := ids.ParseUUID(s)
		if err != nil || id.Version() != 7 {
			return nil, errInvalidID
		}
		sel.Transactions = append(sel.Transactions, id)
	}
	x, err := e.svc.ExportBundle(ctx, sel, req.GetConsistencyFrom())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ExportBundleResponse{
		Bundle: x.Bundle, Entries: int32(x.Entries), Receipts: int32(x.Receipts), CheckpointSize: x.CheckpointSize, //nolint:gosec // G115: bounded by the selection limits
	}, nil
}

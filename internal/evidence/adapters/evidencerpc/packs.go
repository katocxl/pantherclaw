// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package evidencerpc

import (
	"context"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

var packStates = map[string]pantherclawv1.EvidencePackState{
	"BUILDING": pantherclawv1.EvidencePackState_EVIDENCE_PACK_STATE_BUILDING,
	"READY":    pantherclawv1.EvidencePackState_EVIDENCE_PACK_STATE_READY,
	"FAILED":   pantherclawv1.EvidencePackState_EVIDENCE_PACK_STATE_FAILED,
	"EXPIRED":  pantherclawv1.EvidencePackState_EVIDENCE_PACK_STATE_EXPIRED,
}

func packProto(p evapp.Pack) *pantherclawv1.EvidencePack {
	return &pantherclawv1.EvidencePack{
		Id: p.ID.String(), State: packStates[p.State], Scope: p.ScopeJSON, CreatedBy: p.CreatedBy.String(),
		Include: &pantherclawv1.PackContents{
			Receipts: p.Include.Receipts, Versions: p.Include.Versions, Approvals: p.Include.Approvals,
			Containment: p.Include.Containment, Captures: p.Include.Captures,
		},
		CreateTime: ts(p.Created), ReadyTime: ts(p.Ready), ExpireTime: ts(p.Expires), Items: int32(p.Items), //nolint:gosec // G115: ≤ 20,000
		ContentSize: p.ContentSize, ContentSha256: p.ContentSHA256, Manifest: p.Manifest, ErrorCode: p.ErrorCode,
	}
}

func parseID(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil || id.Version() != 7 {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

// CreateEvidencePack implements EvidenceServiceHandler.
func (e *Evidence) CreateEvidencePack(ctx context.Context, req *pantherclawv1.CreateEvidencePackRequest) (*pantherclawv1.CreateEvidencePackResponse, error) {
	in := req.GetInclude()
	r := evapp.PackRequest{Include: pack.Include{
		Receipts: in.GetReceipts(), Versions: in.GetVersions(), Approvals: in.GetApprovals(), Containment: in.GetContainment(),
		Captures: in.GetCaptures(),
	}}
	rangeOf := func(tr *pantherclawv1.PackTimeRange) {
		if tr == nil {
			return
		}
		from, to := tr.GetStartTime().AsTime(), tr.GetEndTime().AsTime()
		r.From, r.To = &from, &to
	}
	var err error
	switch s := req.GetScope().(type) {
	case *pantherclawv1.CreateEvidencePackRequest_Transactions:
		r.Kind = pack.ScopeTransactions
		for _, raw := range s.Transactions.GetIds() {
			id, err := parseID(raw)
			if err != nil {
				return nil, err
			}
			r.Transactions = append(r.Transactions, id)
		}
	case *pantherclawv1.CreateEvidencePackRequest_RunId:
		r.Kind = pack.ScopeRun
		if r.Run, err = parseID(s.RunId); err != nil {
			return nil, err
		}
		rangeOf(req.GetWithin())
	case *pantherclawv1.CreateEvidencePackRequest_AgentId:
		r.Kind = pack.ScopeAgent
		if r.Agent, err = parseID(s.AgentId); err != nil {
			return nil, err
		}
		rangeOf(req.GetWithin())
	case *pantherclawv1.CreateEvidencePackRequest_TimeRange:
		r.Kind = pack.ScopeTimeRange
		rangeOf(s.TimeRange)
	}
	if req.GetWithin() != nil && r.Kind != pack.ScopeRun && r.Kind != pack.ScopeAgent {
		return nil, evapp.ErrBadPackScope
	}
	p, err := e.svc.CreateEvidencePack(ctx, r)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateEvidencePackResponse{Pack: packProto(p)}, nil
}

// GetEvidencePack implements EvidenceServiceHandler.
func (e *Evidence) GetEvidencePack(ctx context.Context, req *pantherclawv1.GetEvidencePackRequest) (*pantherclawv1.GetEvidencePackResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	p, err := e.svc.GetEvidencePack(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetEvidencePackResponse{Pack: packProto(p)}, nil
}

// ListEvidencePacks implements EvidenceServiceHandler.
func (e *Evidence) ListEvidencePacks(ctx context.Context, req *pantherclawv1.ListEvidencePacksRequest) (*pantherclawv1.ListEvidencePacksResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	p, err := e.svc.ListEvidencePacks(ctx, pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListEvidencePacksResponse{NextPageToken: p.Next}
	for _, it := range p.Items {
		out.Packs = append(out.Packs, packProto(it))
	}
	return out, nil
}

// DownloadEvidencePack implements EvidenceServiceHandler.
func (e *Evidence) DownloadEvidencePack(ctx context.Context, req *pantherclawv1.DownloadEvidencePackRequest,
	stream pantherclawv1connect.EvidenceServiceDownloadEvidencePackServerStream,
) error {
	id, err := parseID(req.GetId())
	if err != nil {
		return err
	}
	d, err := e.svc.DownloadEvidencePack(ctx, id)
	if err != nil {
		return err
	}
	total := int64(len(d.Content))
	for off := 0; off < len(d.Content); off += evapp.DownloadChunk {
		end := min(off+evapp.DownloadChunk, len(d.Content))
		if err := stream.Send(&pantherclawv1.DownloadEvidencePackResponse{
			Chunk: d.Content[off:end], Offset: int64(off), TotalSize: total, ContentSha256: d.SHA256,
		}); err != nil {
			return err
		}
	}
	return nil
}

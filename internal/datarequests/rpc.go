// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package datarequests

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

type RPC struct {
	pantherclawv1connect.UnimplementedDataRequestServiceHandler
	Service *Service
}

// Sensitive mutations are only possible through the canonical browser pages.
func (r RPC) CreateExport(context.Context, *pb.CreateExportRequest) (*pb.CreateExportResponse, error) {
	return nil, ErrStepUp
}

func (r RPC) RequestDeletion(context.Context, *pb.RequestDeletionRequest) (*pb.RequestDeletionResponse, error) {
	return nil, ErrStepUp
}

func (r RPC) requestProto(ctx context.Context, v dbq.PcDataRequest) (*pb.DataRequest, error) {
	out := &pb.DataRequest{Id: v.ID.String(), Kind: pb.DataRequestKind(pb.DataRequestKind_value["DATA_REQUEST_KIND_"+v.Kind]), State: pb.DataRequestState(pb.DataRequestState_value["DATA_REQUEST_STATE_"+v.State]), CreateTime: timestamppb.New(v.CreatedAt), TotalSize: v.TotalSize}
	if v.CreatedBy != nil {
		out.CreatedBy = v.CreatedBy.String()
	}
	if v.ReadyAt != nil {
		out.ReadyTime = timestamppb.New(*v.ReadyAt)
	}
	if v.ExpiresAt != nil {
		out.ExpireTime = timestamppb.New(*v.ExpiresAt)
	}
	if v.Manifest != nil {
		out.Manifest = *v.Manifest
	}
	if v.ErrorCode != nil {
		out.ErrorCode = *v.ErrorCode
	}
	if v.WindowEnd != nil {
		out.WindowEndTime = timestamppb.New(*v.WindowEnd)
	}
	if v.CanceledAt != nil {
		out.CancelTime = timestamppb.New(*v.CanceledAt)
	}
	if v.CanceledBy != nil {
		out.CanceledBy = v.CanceledBy.String()
	}
	if v.Reason != nil {
		out.Reason = pb.DeletionReason_DELETION_REASON_REQUESTED
		if *v.Reason == "lapse_90d" {
			out.Reason = pb.DeletionReason_DELETION_REASON_LAPSE_90D
		}
	}
	if v.State == "READY" {
		err := r.Service.Pool.InTenantTx(ctx, v.OrgID, func(ctx context.Context, tx db.TenantTx) error {
			rows, err := dbq.New(tx).DataRequestPartSizes(ctx, v.OrgID, v.ID)
			if err != nil {
				return err
			}
			for _, p := range rows {
				out.Parts = append(out.Parts, &pb.ExportPart{Number: p.Number, Size: p.Size, Sha256: p.Sha256})
			}
			return nil
		}, db.ReadOnly())
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func parseRequestID(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return id, pcerr.New(pcerr.InvalidArgument, "INVALID_DATA_REQUEST", "invalid data request id")
	}
	return id, nil
}

func (r RPC) GetDataRequest(ctx context.Context, in *pb.GetDataRequestRequest) (*pb.GetDataRequestResponse, error) {
	id, err := parseRequestID(in.GetId())
	if err != nil {
		return nil, err
	}
	v, err := r.Service.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	out, err := r.requestProto(ctx, v)
	return &pb.GetDataRequestResponse{Request: out}, err
}

func (r RPC) ListDataRequests(ctx context.Context, in *pb.ListDataRequestsRequest) (*pb.ListDataRequestsResponse, error) {
	var before ids.UUID
	if in.GetPageToken() != "" {
		raw, err := base64.RawURLEncoding.DecodeString(in.GetPageToken())
		if err != nil {
			return nil, pcerr.New(pcerr.InvalidArgument, "INVALID_PAGE", "invalid page token")
		}
		before, err = ids.ParseUUID(string(raw))
		if err != nil {
			return nil, pcerr.New(pcerr.InvalidArgument, "INVALID_PAGE", "invalid page token")
		}
	}
	n := in.GetPageSize()
	if n == 0 {
		n = 50
	}
	rows, err := r.Service.List(ctx, before, n)
	if err != nil {
		return nil, err
	}
	out := &pb.ListDataRequestsResponse{}
	for _, v := range rows {
		p, err := r.requestProto(ctx, v)
		if err != nil {
			return nil, err
		}
		out.Requests = append(out.Requests, p)
	}
	if len(rows) == int(n) {
		out.NextPageToken = base64.RawURLEncoding.EncodeToString([]byte(rows[len(rows)-1].ID.String()))
	}
	return out, nil
}

func (r RPC) CancelDeletion(ctx context.Context, in *pb.CancelDeletionRequest) (*pb.CancelDeletionResponse, error) {
	id, err := parseRequestID(in.GetId())
	if err != nil {
		return nil, err
	}
	v, err := r.Service.Cancel(ctx, id)
	if err != nil {
		return nil, err
	}
	p, err := r.requestProto(ctx, v)
	return &pb.CancelDeletionResponse{Request: p}, err
}

func (r RPC) DownloadExport(ctx context.Context, in *pb.DownloadExportRequest, stream pantherclawv1connect.DataRequestServiceDownloadExportServerStream) error {
	id, err := parseRequestID(in.GetId())
	if err != nil {
		return err
	}
	p, err := r.Service.Download(ctx, id, in.GetPart())
	if err != nil {
		return err
	}
	const chunk = 1 << 20
	for off := 0; off < len(p.Content); off += chunk {
		if err := stream.Send(&pb.DownloadExportResponse{Chunk: p.Content[off:min(off+chunk, len(p.Content))], Offset: int64(off), TotalSize: int64(len(p.Content)), Sha256: p.Sha256}); err != nil {
			return err
		}
	}
	return nil
}

func (r RPC) GetDeletionRecord(ctx context.Context, in *pb.GetDeletionRecordRequest) (*pb.GetDeletionRecordResponse, error) {
	org, err := ids.Parse[ids.Org](in.GetOrgId())
	if err != nil {
		return nil, ErrNotFound
	}
	v, err := r.Service.DeletionRecord(ctx, org)
	if err != nil {
		return nil, err
	}
	var rec DeletionRecord
	if err := json.Unmarshal(v.Record, &rec); err != nil {
		return nil, err
	}
	out := &pb.DeletionRecord{OrgId: rec.Org, Reason: pb.DeletionReason_DELETION_REASON_REQUESTED, RequestedByAccount: rec.RequestedByAccount, RequestTime: timestamppb.New(rec.RequestTime), WindowEndTime: timestamppb.New(rec.WindowEndTime), StartTime: timestamppb.New(rec.StartTime), CompleteTime: timestamppb.New(rec.CompleteTime), Verified: rec.Verified, BackupExpireTime: timestamppb.New(rec.BackupExpireTime), SignedRecord: v.SignedRecord}
	if rec.Reason == "lapse_90d" {
		out.Reason = pb.DeletionReason_DELETION_REASON_LAPSE_90D
	}
	for _, t := range rec.Tables {
		out.Tables = append(out.Tables, &pb.DeletionTableCount{Table: t.Table, Rows: t.Rows})
	}
	return &pb.GetDeletionRecordResponse{Record: out}, nil
}

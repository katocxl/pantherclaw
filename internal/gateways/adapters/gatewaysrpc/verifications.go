// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"
	"time"

	"connectrpc.com/connect/v2"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// Verifications leases verification tasks and takes their reports
// (transactions app, G0 M7).
type Verifications interface {
	Claim(ctx context.Context, org ids.OrgID, gateway ids.UUID, limit int) ([]txapp.Lease, error)
	Report(ctx context.Context, org ids.OrgID, gateway ids.UUID, r txapp.Report) (txapp.Applied, error)
}

// WithVerifications serves ClaimVerifications and ReportObservation from v.
func (h *GatewayHandler) WithVerifications(v Verifications) *GatewayHandler {
	h.verifications = v
	return h
}

// ClaimVerifications implements GatewayServiceHandler, on the mTLS
// listener only (gateway.verify): the org and the gateway come from the
// certificate alone, so a gateway leases only its own connections' tasks
// (HR-190).
func (h *GatewayHandler) ClaimVerifications(ctx context.Context, req *pb.ClaimVerificationsRequest) (*pb.ClaimVerificationsResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	if h.verifications == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, "verifications are not served here")
	}
	leases, err := h.verifications.Claim(ctx, id.Org, id.Gateway, int(req.GetMaxTasks()))
	if err != nil {
		return nil, err
	}
	out := &pb.ClaimVerificationsResponse{}
	for _, l := range leases {
		out.Leases = append(out.Leases, &pb.VerificationLease{
			TaskId: l.Task.String(), Lease: l.Secret, Purpose: string(l.Purpose), ConnectionId: l.Connection.String(),
			Operation: l.Operation, Request: l.Request, Correlate: l.Correlate, Attempt: int32(min(l.Attempt, 1000)), //nolint:gosec // G115: clamped
		})
	}
	return out, nil
}

// ReportObservation implements GatewayServiceHandler, on the mTLS
// listener only (gateway.verify): a report counts only under the calling
// gateway's live lease (HR-190).
func (h *GatewayHandler) ReportObservation(ctx context.Context, req *pb.ReportObservationRequest) (*pb.ReportObservationResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	if h.verifications == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, "verifications are not served here")
	}
	task, err := ids.ParseUUID(req.GetTaskId())
	if err != nil {
		return nil, errInvalidID
	}
	r := txapp.Report{
		Task: task, Secret: req.GetLease(), HTTPStatus: int(req.GetHttpStatus()), Found: req.GetFound(), Complete: req.GetComplete(),
		Fields: req.GetFields(), ResponseDigest: req.GetResponseDigest(),
	}
	for _, it := range req.GetItems() {
		item := txapp.TargetLogItem{ObjectRef: it.GetObjectRef(), Correlation: it.GetCorrelation()}
		if c := it.GetCreated(); c > 0 {
			item.Created = time.Unix(c, 0).UTC()
		}
		r.Items = append(r.Items, item)
	}
	a, err := h.verifications.Report(ctx, id.Org, id.Gateway, r)
	if err != nil {
		return nil, err
	}
	return &pb.ReportObservationResponse{ObservationId: a.Observation.String(), EffectState: string(a.State), Done: a.Done}, nil
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package coveragerpc

import (
	"context"
	"encoding/hex"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

func snapshotProto(s app.SnapshotRecord) *pantherclawv1.CoverageSnapshot {
	state, _ := domain.ParseState(s.State)
	out := &pantherclawv1.CoverageSnapshot{
		Id: s.ID.String(), State: states[state], Reasons: s.Reasons, ClosureId: idText(s.ClosureID),
		Scope:       scopeProto(domain.Scope{Agent: s.AgentID, Connection: s.ConnectionID, Operation: s.Operation}),
		LastValidId: idText(s.LastValidID), InvalidationId: idText(s.InvalidationID), ComputeTime: ts(s.ComputedAt),
		ExpireTime: tsp(s.ExpiresAt), LedgerEntryId: s.LedgerEntryID.String(),
		EntryDigest: "sha256:" + hex.EncodeToString(s.BodySha256),
	}
	out.ExclusionIds = append(out.ExclusionIds, s.Body.Exclusions...)
	for _, rt := range s.Body.Routes {
		out.Routes = append(out.Routes, &pantherclawv1.CoverageRoute{
			Id: rt.Route, Kind: kinds[domain.RouteKind(rt.Kind)], Channel: rt.Channel, Locator: rt.Locator,
			Status: statuses[domain.RouteStatus(rt.Status)], ClosureId: rt.Closure,
		})
	}
	return out
}

// GetSnapshot implements CoverageServiceHandler.
func (h *Handler) GetSnapshot(ctx context.Context, req *pantherclawv1.GetSnapshotRequest) (*pantherclawv1.GetSnapshotResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	s, err := h.svc.GetSnapshot(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetSnapshotResponse{Snapshot: snapshotProto(s)}, nil
}

// ListSnapshots implements CoverageServiceHandler.
func (h *Handler) ListSnapshots(ctx context.Context, req *pantherclawv1.ListSnapshotsRequest) (*pantherclawv1.ListSnapshotsResponse, error) {
	agent, err := idOf(req.GetScope().GetAgentId())
	if err != nil {
		return nil, err
	}
	conn, err := idOf(req.GetScope().GetConnectionId())
	if err != nil {
		return nil, err
	}
	sc := domain.Scope{Agent: agent, Connection: conn, Operation: req.GetScope().GetOperation()}
	rows, next, err := h.svc.ListSnapshots(ctx, sc, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListSnapshotsResponse{NextPageToken: next}
	for _, s := range rows {
		out.Snapshots = append(out.Snapshots, snapshotProto(s))
	}
	return out, nil
}

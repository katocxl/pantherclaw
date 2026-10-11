// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package coveragerpc

import (
	"context"
	"encoding/hex"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var statuses = map[domain.RouteStatus]pantherclawv1.CoverageRouteStatus{
	domain.StatusMediated:    pantherclawv1.CoverageRouteStatus_COVERAGE_ROUTE_STATUS_MEDIATED,
	domain.StatusMonitored:   pantherclawv1.CoverageRouteStatus_COVERAGE_ROUTE_STATUS_MONITORED,
	domain.StatusCooperative: pantherclawv1.CoverageRouteStatus_COVERAGE_ROUTE_STATUS_COOPERATIVE,
	domain.StatusOpaque:      pantherclawv1.CoverageRouteStatus_COVERAGE_ROUTE_STATUS_OPAQUE,
	domain.StatusClosed:      pantherclawv1.CoverageRouteStatus_COVERAGE_ROUTE_STATUS_CLOSED,
	domain.StatusPossible:    pantherclawv1.CoverageRouteStatus_COVERAGE_ROUTE_STATUS_POSSIBLE,
	domain.StatusNotObserved: pantherclawv1.CoverageRouteStatus_COVERAGE_ROUTE_STATUS_NOT_OBSERVED,
	domain.StatusProposed:    pantherclawv1.CoverageRouteStatus_COVERAGE_ROUTE_STATUS_PROPOSED,
	domain.StatusExcluded:    pantherclawv1.CoverageRouteStatus_COVERAGE_ROUTE_STATUS_EXCLUDED,
}

func idText(id *ids.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func scopeProto(sc domain.Scope) *pantherclawv1.CoverageScope {
	return &pantherclawv1.CoverageScope{
		AgentId: sc.Agent.String(), ConnectionId: sc.Connection.String(), Operation: sc.Operation,
	}
}

func exclusionProto(x dbq.PcCoverageExclusion) *pantherclawv1.CoverageExclusion {
	return &pantherclawv1.CoverageExclusion{
		Id: x.ID.String(), AgentId: idText(x.AgentID), ConnectionId: x.ConnectionID.String(), Operation: str(x.Operation),
		RouteKind: kinds[domain.RouteKind(str(x.RouteKind))], Reason: x.Reason, State: x.State,
		CreatedBy: x.CreatedBy.String(), CreateTime: ts(x.CreatedAt), ExpireTime: ts(x.ExpiresAt),
		RevokedBy: idText(x.RevokedBy), RevokeTime: tsp(x.RevokedAt),
	}
}

// recordProto translates a record; full adds routes, changes and
// exclusions.
func recordProto(r app.Record, full bool) *pantherclawv1.CoverageRecord {
	out := &pantherclawv1.CoverageRecord{
		Scope: scopeProto(r.Scope), State: states[r.State], ComputedState: states[r.Computed], Reasons: r.Reasons,
	}
	if r.Snapshot != nil {
		out.SnapshotId, out.SnapshotDigest = r.Snapshot.ID.String(), "sha256:"+hex.EncodeToString(r.Snapshot.BodySha256)
		out.ComputeTime, out.ExpireTime, out.ClosureId = ts(r.Snapshot.ComputedAt), tsp(r.Snapshot.ExpiresAt), idText(r.Snapshot.ClosureID)
	}
	if lv := r.LastValid; lv != nil {
		out.LastValid = &pantherclawv1.CoverageLastValid{
			SnapshotId: lv.ID.String(), ComputeTime: ts(lv.ComputedAt), ExpireTime: tsp(lv.ExpiresAt),
			ClosureId: idText(lv.ClosureID), LapseReason: r.Lapse,
		}
	}
	if !full {
		return out
	}
	for _, rt := range r.Body.Routes {
		out.Routes = append(out.Routes, &pantherclawv1.CoverageRoute{
			Id: idText(rt.Route), Kind: kinds[domain.RouteKind(rt.Kind)], Channel: rt.Channel, Locator: rt.Locator,
			Status: statuses[domain.RouteStatus(rt.Status)], ClosureId: idText(rt.Closure),
		})
	}
	for _, c := range r.Changes {
		out.Invalidations = append(out.Invalidations, &pantherclawv1.CoverageInvalidation{
			Id: c.ID.String(), Kind: c.Kind, ConnectionId: c.ConnectionID.String(), AgentId: idText(c.AgentID),
			SubjectId: idText(c.SubjectID), Detail: str(c.Detail), OccurTime: ts(c.OccurredAt), ReassessTime: tsp(c.ReassessedAt),
		})
	}
	for _, x := range r.Exclusions {
		out.Exclusions = append(out.Exclusions, exclusionProto(x))
	}
	return out
}

// GetCoverage implements CoverageServiceHandler.
func (h *Handler) GetCoverage(ctx context.Context, req *pantherclawv1.GetCoverageRequest) (*pantherclawv1.GetCoverageResponse, error) {
	agent, err := idOf(req.GetScope().GetAgentId())
	if err != nil {
		return nil, err
	}
	conn, err := idOf(req.GetScope().GetConnectionId())
	if err != nil {
		return nil, err
	}
	r, err := h.svc.GetCoverage(ctx, domain.Scope{Agent: agent, Connection: conn, Operation: req.GetScope().GetOperation()})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetCoverageResponse{Record: recordProto(r, true)}, nil
}

// ListCoverage implements CoverageServiceHandler.
func (h *Handler) ListCoverage(ctx context.Context, req *pantherclawv1.ListCoverageRequest) (*pantherclawv1.ListCoverageResponse, error) {
	f, err := filterOf(req.AgentId, req.ConnectionId)
	if err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListCoverage(ctx, f, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListCoverageResponse{NextPageToken: next}
	for _, r := range rows {
		out.Records = append(out.Records, recordProto(r, false))
	}
	return out, nil
}

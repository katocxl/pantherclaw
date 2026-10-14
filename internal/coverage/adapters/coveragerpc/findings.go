// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package coveragerpc

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

func findingProto(f dbq.PcCoverageFinding) *pantherclawv1.CoverageFinding {
	return &pantherclawv1.CoverageFinding{
		Id: f.ID.String(), Kind: f.Kind, ConnectionId: idText(f.ConnectionID), AgentId: idText(f.AgentID), Subject: f.Subject,
		Declared: f.Declared, Held: f.Held, Used: f.Used, Excess: f.Excess, Severity: f.Severity, State: f.State,
		FirstSeenTime: ts(f.FirstSeenAt), LastSeenTime: ts(f.LastSeenAt), ResolveTime: tsp(f.ResolvedAt),
		DismissedBy: idText(f.DismissedBy), DismissReason: str(f.DismissReason),
	}
}

// ListFindings implements CoverageServiceHandler.
func (h *Handler) ListFindings(ctx context.Context, req *pantherclawv1.ListFindingsRequest) (*pantherclawv1.ListFindingsResponse, error) {
	conn, err := optID(req.ConnectionId)
	if err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListFindings(ctx, req.State, conn, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListFindingsResponse{NextPageToken: next}
	for _, f := range rows {
		out.Findings = append(out.Findings, findingProto(f))
	}
	return out, nil
}

// AcknowledgeFinding implements CoverageServiceHandler.
func (h *Handler) AcknowledgeFinding(ctx context.Context, req *pantherclawv1.AcknowledgeFindingRequest) (*pantherclawv1.AcknowledgeFindingResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	f, err := h.svc.AcknowledgeFinding(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.AcknowledgeFindingResponse{Finding: findingProto(f)}, nil
}

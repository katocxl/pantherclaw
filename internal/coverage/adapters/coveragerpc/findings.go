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

// ListCoverageFindings implements CoverageServiceHandler.
func (h *Handler) ListCoverageFindings(ctx context.Context, req *pantherclawv1.ListCoverageFindingsRequest) (*pantherclawv1.ListCoverageFindingsResponse, error) {
	conn, err := optID(req.ConnectionId)
	if err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListFindings(ctx, req.State, conn, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListCoverageFindingsResponse{NextPageToken: next}
	for _, f := range rows {
		out.Findings = append(out.Findings, findingProto(f))
	}
	return out, nil
}

// DismissCoverageFinding implements CoverageServiceHandler.
func (h *Handler) DismissCoverageFinding(ctx context.Context, req *pantherclawv1.DismissCoverageFindingRequest) (*pantherclawv1.DismissCoverageFindingResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	f, err := h.svc.DismissFinding(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DismissCoverageFindingResponse{Finding: findingProto(f)}, nil
}

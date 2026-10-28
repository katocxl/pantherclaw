// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package coveragerpc

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// GetCoverageGraph implements CoverageServiceHandler (F277).
func (h *Handler) GetCoverageGraph(ctx context.Context, req *pantherclawv1.GetCoverageGraphRequest) (*pantherclawv1.GetCoverageGraphResponse, error) {
	agent, err := idOf(req.GetAgentId())
	if err != nil {
		return nil, err
	}
	conn, err := optID(req.ConnectionId)
	if err != nil {
		return nil, err
	}
	g, err := h.svc.GetCoverageGraph(ctx, agent, app.GraphFilter{Connection: conn, Operation: req.Operation})
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetCoverageGraphResponse{BoundaryState: g.BoundaryState, ScopeLimited: g.ScopeLimited}
	for _, n := range g.Nodes {
		out.Nodes = append(out.Nodes, &pantherclawv1.CoverageGraphNode{
			Id: n.ID, Kind: n.Kind, Label: n.Label, RouteKind: n.RouteKind, RouteStatus: n.RouteStatus, Control: n.Control,
			ClosureId: n.Closure,
		})
	}
	for _, e := range g.Edges {
		out.Edges = append(out.Edges, &pantherclawv1.CoverageGraphEdge{From: e.From, To: e.To})
	}
	return out, nil
}

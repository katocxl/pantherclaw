// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package coveragerpc

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func routeProto(r dbq.PcCoverageRoute) *pantherclawv1.CoverageRoute {
	return &pantherclawv1.CoverageRoute{
		Id: r.ID.String(), Kind: kinds[domain.RouteKind(r.Kind)], Channel: str(r.Channel), Locator: str(r.Locator),
		Observation: r.Observation, Source: r.Source, Mode: str(r.Mode), FirstSeenTime: ts(r.FirstSeenAt),
		LastSeenTime: ts(r.LastSeenAt),
	}
}

// ListRoutes implements CoverageServiceHandler.
func (h *Handler) ListRoutes(ctx context.Context, req *pantherclawv1.ListRoutesRequest) (*pantherclawv1.ListRoutesResponse, error) {
	f, err := filterOf(req.AgentId, req.ConnectionId)
	if err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListRoutes(ctx, f, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListRoutesResponse{NextPageToken: next}
	for _, r := range rows {
		out.Routes = append(out.Routes, routeProto(r))
	}
	return out, nil
}

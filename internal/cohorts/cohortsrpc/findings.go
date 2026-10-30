// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package cohortsrpc

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/cohorts"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// GetCohortFindings implements CohortServiceHandler (G0 M18 D154, HR-480).
func (h *Handler) GetCohortFindings(ctx context.Context, r *pantherclawv1.GetCohortFindingsRequest) (*pantherclawv1.GetCohortFindingsResponse, error) {
	id, err := parse(r.GetCohortId())
	if err != nil {
		return nil, err
	}
	f, err := h.svc.GetFindings(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetCohortFindingsResponse{
		Agents:   int32(f.Agents), //nolint:gosec // ≤ 2000
		Coverage: countPB(f.Coverage), Departures: countPB(f.Departures), FailedTargets: countPB(f.FailedTargets),
		ActiveExceptions: countPB(f.ActiveExceptions), Truncated: f.Truncated,
	}, nil
}

func countPB(c cohorts.Count) *pantherclawv1.CohortFindingCount {
	return &pantherclawv1.CohortFindingCount{Findings: c.Findings, Agents: c.Agents, Shown: c.Shown}
}

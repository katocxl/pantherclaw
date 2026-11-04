// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package modelusagerpc serves ModelUsageService over Connect (G0 M29
// D825).
package modelusagerpc

import (
	"context"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/modelusage/app"
	"github.com/katocxl/pantherclaw/internal/modelusage/domain"
)

// Handler serves ModelUsageService.
type Handler struct {
	pantherclawv1connect.UnimplementedModelUsageServiceHandler
	svc *app.Service
}

// New returns the ModelUsageService handler.
func New(svc *app.Service) *Handler { return &Handler{svc: svc} }

var groupings = map[pantherclawv1.TokenReportGroupBy]domain.GroupBy{
	pantherclawv1.TokenReportGroupBy_TOKEN_REPORT_GROUP_BY_TEAM:       domain.ByTeam,
	pantherclawv1.TokenReportGroupBy_TOKEN_REPORT_GROUP_BY_AGENT:      domain.ByAgent,
	pantherclawv1.TokenReportGroupBy_TOKEN_REPORT_GROUP_BY_CONNECTION: domain.ByConnection,
	pantherclawv1.TokenReportGroupBy_TOKEN_REPORT_GROUP_BY_MODEL:      domain.ByModel,
}

// GetTokenReport implements ModelUsageService.
func (h *Handler) GetTokenReport(ctx context.Context, req *pantherclawv1.GetTokenReportRequest) (*pantherclawv1.GetTokenReportResponse, error) {
	by, ok := groupings[req.GetGroupBy()]
	if !ok {
		return nil, app.ErrInvalidGroupBy
	}
	r, err := h.svc.Report(ctx, app.ReportRequest{
		Month: req.GetMonth(), By: by, PageSize: req.GetPageSize(), PageToken: req.GetPageToken(),
	})
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetTokenReportResponse{NextPageToken: r.Next, Statement: r.Statement}
	for _, row := range r.Rows {
		pr := &pantherclawv1.TokenReportRow{
			Key: row.Key, Label: row.Label, Calls: row.Calls, UnreportedCalls: row.UnreportedCalls, UnknownCalls: row.UnknownCalls,
			InputTokens: row.InputTokens, OutputTokens: row.OutputTokens,
			CacheReadTokens: row.CacheReadTokens, CacheWriteTokens: row.CacheWriteTokens, TotalTokens: row.TotalTokens,
		}
		for _, e := range row.Estimates {
			pr.Estimates = append(pr.Estimates, &pantherclawv1.Estimate{Currency: string(e.Currency), Amount: e.Amount.String()})
		}
		out.Rows = append(out.Rows, pr)
	}
	return out, nil
}

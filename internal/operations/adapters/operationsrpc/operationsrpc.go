// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package operationsrpc serves OperationsService over Connect (G0 M10
// D33, HR-258): the work queue, the summary and the evidence status, each
// read under the caller's permissions and stamped with scope and time.
package operationsrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/operations"
	"github.com/katocxl/pantherclaw/internal/search/adapters/searchrpc"
)

// Handler serves OperationsService.
type Handler struct {
	pantherclawv1connect.UnimplementedOperationsServiceHandler
	svc *operations.Service
}

// New returns the OperationsService handler.
func New(svc *operations.Service) *Handler { return &Handler{svc: svc} }

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

// GetWorkQueue implements OperationsServiceHandler.
func (h *Handler) GetWorkQueue(ctx context.Context, _ *pantherclawv1.GetWorkQueueRequest) (*pantherclawv1.GetWorkQueueResponse, error) {
	q, err := h.svc.GetWorkQueue(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetWorkQueueResponse{
		AsOfTime: timestamppb.New(q.AsOf), ScopeWhole: q.Whole, Truncated: q.Truncated, PendingSources: q.Pending,
	}
	for _, it := range q.Items {
		w := &pantherclawv1.WorkItem{
			Kind: string(it.Kind), Id: it.ID, Title: it.Title, Severity: it.Severity, State: it.State,
			SinceTime: timestamppb.New(it.Since), DeadlineTime: ts(it.Deadline), AgentIds: it.Agents, Test: it.Test,
		}
		for _, a := range it.Actions {
			w.Actions = append(w.Actions, &pantherclawv1.WorkAction{Name: a.Name, Permission: string(a.Permission), Target: a.Target})
		}
		out.Items = append(out.Items, w)
	}
	return out, nil
}

// GetSummary implements OperationsServiceHandler.
func (h *Handler) GetSummary(ctx context.Context, _ *pantherclawv1.GetSummaryRequest) (*pantherclawv1.GetSummaryResponse, error) {
	s, err := h.svc.GetSummary(ctx)
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int32, len(s.Counts))
	for k, v := range s.Counts {
		counts[k] = int32(v) //nolint:gosec // G115: bounded by the queue size
	}
	return &pantherclawv1.GetSummaryResponse{
		AsOfTime: timestamppb.New(s.AsOf), ScopeWhole: s.Whole, Scope: s.Scope, Counts: counts,
		Truncated: s.Truncated, Unknown: s.Unknown, Statement: s.Statement,
	}, nil
}

// GetEvidenceStatus implements OperationsServiceHandler.
func (h *Handler) GetEvidenceStatus(ctx context.Context, _ *pantherclawv1.GetEvidenceStatusRequest) (
	*pantherclawv1.GetEvidenceStatusResponse, error,
) {
	es, err := h.svc.GetEvidenceStatus(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetEvidenceStatusResponse{AsOfTime: timestamppb.New(es.AsOf)}
	for _, src := range es.Sources {
		out.Sources = append(out.Sources, &pantherclawv1.SourceStatus{
			Kind: src.Kind, Name: src.Name, Id: src.ID, LastSeenTime: ts(src.LastSeen), Freshness: string(src.Freshness),
			Gap: src.Gap(), Lag: src.Lag, Note: src.Note,
		})
	}
	return out, nil
}

// GetMetrics implements OperationsServiceHandler.
func (h *Handler) GetMetrics(ctx context.Context, req *pantherclawv1.GetMetricsRequest) (*pantherclawv1.GetMetricsResponse, error) {
	m, err := h.svc.GetMetrics(ctx, req.GetMetrics(), req.GetStartTime().AsTime(), req.GetEndTime().AsTime())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetMetricsResponse{
		AsOfTime: timestamppb.New(m.AsOf), StartTime: timestamppb.New(m.Start), EndTime: timestamppb.New(m.End),
	}
	for _, s := range m.Series {
		ps := &pantherclawv1.MetricSeries{Metric: s.Metric, Dimension: s.Dimension}
		for _, p := range s.Points {
			mp := &pantherclawv1.MetricPoint{BucketTime: timestamppb.New(p.Bucket), State: string(p.State), Value: p.Value}
			if p.Drill != nil {
				mp.DrillQuery, mp.DrillBuiltin = searchrpc.SpecProto(*p.Drill)
			} else {
				mp.NoDrill = true
			}
			ps.Points = append(ps.Points, mp)
		}
		out.Series = append(out.Series, ps)
	}
	return out, nil
}

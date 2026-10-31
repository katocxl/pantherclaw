// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package outcomesrpc serves OutcomeService (G0 M21 D303, F774).
package outcomesrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/outcomes"
)

// Handler serves OutcomeService.
type Handler struct {
	pantherclawv1connect.UnimplementedOutcomeServiceHandler
	svc *outcomes.Service
}

// New returns the OutcomeService handler.
func New(svc *outcomes.Service) *Handler { return &Handler{svc: svc} }

// GetOutcomeMetrics implements OutcomeServiceHandler.
func (h *Handler) GetOutcomeMetrics(ctx context.Context, req *pantherclawv1.GetOutcomeMetricsRequest) (*pantherclawv1.GetOutcomeMetricsResponse, error) {
	r, err := h.svc.GetMetrics(ctx, req.GetMetrics(), int(req.GetWindowDays()), req.GetStartTime().AsTime(), req.GetEndTime().AsTime())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetOutcomeMetricsResponse{
		AsOfTime: timestamppb.New(r.AsOf), StartTime: timestamppb.New(r.Start), EndTime: timestamppb.New(r.End),
		WindowDays: req.GetWindowDays(),
	}
	for _, s := range r.Series {
		sr := &pantherclawv1.OutcomeSeries{
			Metric: s.Definition.Name, Group: s.Definition.Group, Dimension: s.Dimension, Kind: kinds[s.Definition.Kind],
			Scope: s.Scope, Title: s.Definition.Title, Measures: s.Definition.Measures, NotSeen: s.Definition.NotSeen,
			DefinitionStatus: s.Definition.Status,
		}
		for _, p := range s.Points {
			sr.Points = append(sr.Points, point(p))
		}
		out.Series = append(out.Series, sr)
	}
	return out, nil
}

var kinds = map[outcomes.Kind]pantherclawv1.OutcomeMetricKind{
	outcomes.KindDuration: pantherclawv1.OutcomeMetricKind_OUTCOME_METRIC_KIND_DURATION,
	outcomes.KindShare:    pantherclawv1.OutcomeMetricKind_OUTCOME_METRIC_KIND_SHARE,
}

var states = map[outcomes.PointState]pantherclawv1.OutcomePointState{
	outcomes.Collected:    pantherclawv1.OutcomePointState_OUTCOME_POINT_STATE_COLLECTED,
	outcomes.NotCollected: pantherclawv1.OutcomePointState_OUTCOME_POINT_STATE_NOT_COLLECTED,
	outcomes.NoSample:     pantherclawv1.OutcomePointState_OUTCOME_POINT_STATE_NO_SAMPLE,
	outcomes.Restricted:   pantherclawv1.OutcomePointState_OUTCOME_POINT_STATE_RESTRICTED,
}

func point(p outcomes.Point) *pantherclawv1.OutcomePoint {
	out := &pantherclawv1.OutcomePoint{
		WindowStartTime: timestamppb.New(p.Window.Start), WindowEndTime: timestamppb.New(p.Window.End), State: states[p.State],
		MedianSeconds: p.P50, P90Seconds: p.P90, Share: p.Share, MeasuredCount: p.Measured, UnmeasuredCount: p.Unmeasured,
	}
	if !p.AsOf.IsZero() {
		out.AsOfTime = timestamppb.New(p.AsOf)
	}
	for _, r := range p.Reasons {
		out.Unmeasured = append(out.Unmeasured, &pantherclawv1.OutcomeUnmeasured{Code: r.Code, Count: r.Count, OldestAgeSeconds: r.OldestAgeSeconds})
	}
	return out
}

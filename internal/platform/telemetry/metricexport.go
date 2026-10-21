// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package telemetry

import (
	"context"
	"sync/atomic"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	commonv1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/common/v1"
	metricsv1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/metrics/v1"
	resourcev1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/resource/v1"
)

// metricExporter posts metrics as OTLP MetricsData from the SDK's periodic
// reader, which runs off every request path. A failed export is counted
// and dropped (HR-381); the reader tries again at its next interval.
type metricExporter struct {
	c        *client
	resource *resourcev1.Resource
	failed   atomic.Int64
}

var _ sdkmetric.Exporter = (*metricExporter)(nil)

// Temporality implements sdkmetric.Exporter (cumulative).
func (e *metricExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	return sdkmetric.DefaultTemporalitySelector(k)
}

// Aggregation implements sdkmetric.Exporter.
func (e *metricExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(k)
}

// Export implements sdkmetric.Exporter.
func (e *metricExporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	if err := e.c.post(ctx, metricsPath, metricsData(e.resource, rm)); err != nil {
		e.failed.Add(1)
		return err
	}
	return nil
}

// ForceFlush implements sdkmetric.Exporter (nothing is buffered).
func (e *metricExporter) ForceFlush(context.Context) error { return nil }

// Shutdown implements sdkmetric.Exporter.
func (e *metricExporter) Shutdown(context.Context) error { return nil }

// metricsData converts sums, gauges and histograms with the allow-listed
// attributes (HR-380). Exponential histograms and summaries are not used.
func metricsData(res *resourcev1.Resource, rm *metricdata.ResourceMetrics) *metricsv1.MetricsData {
	out := &metricsv1.ResourceMetrics{Resource: res}
	for _, sm := range rm.ScopeMetrics {
		scope := &metricsv1.ScopeMetrics{Scope: &commonv1.InstrumentationScope{Name: sm.Scope.Name}}
		for _, m := range sm.Metrics {
			pm := &metricsv1.Metric{Name: m.Name, Description: m.Description, Unit: m.Unit}
			switch d := m.Data.(type) {
			case metricdata.Sum[int64]:
				pm.Data = &metricsv1.Metric_Sum{Sum: &metricsv1.Sum{
					DataPoints: numberPoints(d.DataPoints), AggregationTemporality: temporality(d.Temporality), IsMonotonic: d.IsMonotonic,
				}}
			case metricdata.Sum[float64]:
				pm.Data = &metricsv1.Metric_Sum{Sum: &metricsv1.Sum{
					DataPoints: numberPoints(d.DataPoints), AggregationTemporality: temporality(d.Temporality), IsMonotonic: d.IsMonotonic,
				}}
			case metricdata.Gauge[int64]:
				pm.Data = &metricsv1.Metric_Gauge{Gauge: &metricsv1.Gauge{DataPoints: numberPoints(d.DataPoints)}}
			case metricdata.Gauge[float64]:
				pm.Data = &metricsv1.Metric_Gauge{Gauge: &metricsv1.Gauge{DataPoints: numberPoints(d.DataPoints)}}
			case metricdata.Histogram[int64]:
				pm.Data = &metricsv1.Metric_Histogram{Histogram: &metricsv1.Histogram{
					DataPoints: histogramPoints(d.DataPoints), AggregationTemporality: temporality(d.Temporality),
				}}
			case metricdata.Histogram[float64]:
				pm.Data = &metricsv1.Metric_Histogram{Histogram: &metricsv1.Histogram{
					DataPoints: histogramPoints(d.DataPoints), AggregationTemporality: temporality(d.Temporality),
				}}
			default:
				continue
			}
			scope.Metrics = append(scope.Metrics, pm)
		}
		out.ScopeMetrics = append(out.ScopeMetrics, scope)
	}
	return &metricsv1.MetricsData{ResourceMetrics: []*metricsv1.ResourceMetrics{out}}
}

func temporality(t metricdata.Temporality) metricsv1.AggregationTemporality {
	switch t {
	case metricdata.DeltaTemporality:
		return metricsv1.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA
	case metricdata.CumulativeTemporality:
		return metricsv1.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE
	default:
		return metricsv1.AggregationTemporality_AGGREGATION_TEMPORALITY_UNSPECIFIED
	}
}

func numberPoints[N int64 | float64](dps []metricdata.DataPoint[N]) []*metricsv1.NumberDataPoint {
	out := make([]*metricsv1.NumberDataPoint, 0, len(dps))
	for _, dp := range dps {
		p := &metricsv1.NumberDataPoint{
			Attributes: keyValues(dp.Attributes.ToSlice()), StartTimeUnixNano: unixNano(dp.StartTime), TimeUnixNano: unixNano(dp.Time),
		}
		switch v := any(dp.Value).(type) {
		case int64:
			p.Value = &metricsv1.NumberDataPoint_AsInt{AsInt: v}
		case float64:
			p.Value = &metricsv1.NumberDataPoint_AsDouble{AsDouble: v}
		}
		out = append(out, p)
	}
	return out
}

func histogramPoints[N int64 | float64](dps []metricdata.HistogramDataPoint[N]) []*metricsv1.HistogramDataPoint {
	out := make([]*metricsv1.HistogramDataPoint, 0, len(dps))
	for _, dp := range dps {
		sum := float64(dp.Sum)
		p := &metricsv1.HistogramDataPoint{
			Attributes: keyValues(dp.Attributes.ToSlice()), StartTimeUnixNano: unixNano(dp.StartTime), TimeUnixNano: unixNano(dp.Time),
			Count: dp.Count, Sum: &sum, BucketCounts: dp.BucketCounts, ExplicitBounds: dp.Bounds,
		}
		if v, ok := dp.Min.Value(); ok {
			f := float64(v)
			p.Min = &f
		}
		if v, ok := dp.Max.Value(); ok {
			f := float64(v)
			p.Max = &f
		}
		out = append(out, p)
	}
	return out
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package telemetry

import (
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// writeText renders metrics in the Prometheus text exposition format
// (version 0.0.4) for the admin listener's /metrics: counters, gauges and
// histograms, with the allow-listed attributes as labels (HR-380).
func writeText(w io.Writer, rm *metricdata.ResourceMetrics) error {
	var b strings.Builder
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			name := promName(m.Name)
			switch d := m.Data.(type) {
			case metricdata.Sum[int64]:
				header(&b, name, m.Description, sumType(d.IsMonotonic))
				numbers(&b, name, d.DataPoints)
			case metricdata.Sum[float64]:
				header(&b, name, m.Description, sumType(d.IsMonotonic))
				numbers(&b, name, d.DataPoints)
			case metricdata.Gauge[int64]:
				header(&b, name, m.Description, "gauge")
				numbers(&b, name, d.DataPoints)
			case metricdata.Gauge[float64]:
				header(&b, name, m.Description, "gauge")
				numbers(&b, name, d.DataPoints)
			case metricdata.Histogram[int64]:
				header(&b, name, m.Description, "histogram")
				histograms(&b, name, d.DataPoints)
			case metricdata.Histogram[float64]:
				header(&b, name, m.Description, "histogram")
				histograms(&b, name, d.DataPoints)
			}
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func sumType(monotonic bool) string {
	if monotonic {
		return "counter"
	}
	return "gauge"
}

var invalidName = regexp.MustCompile(`[^a-zA-Z0-9_:]`)

// promName maps an instrument name to a Prometheus metric name.
func promName(s string) string { return invalidName.ReplaceAllString(s, "_") }

func header(b *strings.Builder, name, help, typ string) {
	if help != "" {
		fmt.Fprintf(b, "# HELP %s %s\n", name, strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(help))
	}
	fmt.Fprintf(b, "# TYPE %s %s\n", name, typ)
}

// labels renders the allow-listed attributes plus extra, sorted by key.
func labels(set attribute.Set, extra ...string) string {
	var parts []string
	for _, kv := range filtered(set.ToSlice()) {
		parts = append(parts, promName(string(kv.Key))+"="+strconv.Quote(kv.Value.String()))
	}
	for i := 0; i+1 < len(extra); i += 2 {
		parts = append(parts, extra[i]+"="+strconv.Quote(extra[i+1]))
	}
	if len(parts) == 0 {
		return ""
	}
	slices.Sort(parts)
	return "{" + strings.Join(parts, ",") + "}"
}

func numbers[N int64 | float64](b *strings.Builder, name string, dps []metricdata.DataPoint[N]) {
	for _, dp := range dps {
		fmt.Fprintf(b, "%s%s %s\n", name, labels(dp.Attributes), num(float64(dp.Value)))
	}
}

func histograms[N int64 | float64](b *strings.Builder, name string, dps []metricdata.HistogramDataPoint[N]) {
	for _, dp := range dps {
		var cum uint64
		for i, bound := range dp.Bounds {
			cum += dp.BucketCounts[i]
			fmt.Fprintf(b, "%s_bucket%s %d\n", name, labels(dp.Attributes, "le", num(bound)), cum)
		}
		fmt.Fprintf(b, "%s_bucket%s %d\n", name, labels(dp.Attributes, "le", "+Inf"), dp.Count)
		fmt.Fprintf(b, "%s_sum%s %s\n", name, labels(dp.Attributes), num(float64(dp.Sum)))
		fmt.Fprintf(b, "%s_count%s %d\n", name, labels(dp.Attributes), dp.Count)
	}
}

func num(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	case math.IsNaN(f):
		return "NaN"
	default:
		return strconv.FormatFloat(f, 'g', -1, 64)
	}
}

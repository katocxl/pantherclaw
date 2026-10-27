// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package telemetry exports traces and metrics with PantherClaw's own small
// OTLP/HTTP exporter (G0 M13 D30, F5, ADR-0033): the official OpenTelemetry
// SDK records, and this package posts OTLP protobuf messages generated from
// the vendored opentelemetry-proto files (no gRPC). It also serves the
// private admin listener (pprof and /metrics) and puts trace ids in logs.
//
//   - HR-380: every exported span and metric attribute passes Filter, the
//     one fixed allow-list (procedure, code, org id, outcome, durations,
//     sizes and fixed labels); never payloads, secrets, emails, tokens or
//     SQL arguments.
//   - HR-381: the exporter never blocks a request: spans go through a
//     bounded queue and are dropped and counted on overflow or a failed
//     export; metrics are exported off the request path.
//   - HR-382: the admin listener is off by default and refuses any address
//     that is not loopback.
package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// DefaultSampleRatio is the share of traces kept when none is configured;
// spans that end with an error are always kept.
const DefaultSampleRatio = 0.1

// MetricInterval is how often metrics are exported over OTLP.
const MetricInterval = time.Minute

// Config configures Setup.
type Config struct {
	// ServiceName and ServiceVersion name the exported resource.
	ServiceName, ServiceVersion string
	// Endpoint is the OTLP/HTTP base URL; empty turns export off.
	Endpoint string
	// Headers are sent with every export (from telemetry.otlp.headers_file).
	Headers []Header
	// SampleRatio is the share of traces kept (0..1).
	SampleRatio float64
	// Metrics records metrics for the admin listener's /metrics even when
	// export is off.
	Metrics bool
	// Logger receives the SDK's errors (an export failure names its HTTP
	// status only).
	Logger *slog.Logger
}

// Telemetry is what Setup installed.
type Telemetry struct {
	tracer  *sdktrace.TracerProvider
	meter   *sdkmetric.MeterProvider
	reader  *sdkmetric.ManualReader
	spans   *spanQueue
	metrics *metricExporter
}

// Reader is the /metrics reader (nil without metrics).
func (t *Telemetry) Reader() *sdkmetric.ManualReader { return t.reader }

// Enabled reports whether traces are exported.
func (t *Telemetry) Enabled() bool { return t.tracer != nil }

// DroppedSpans is the number of spans dropped so far (HR-381).
func (t *Telemetry) DroppedSpans() int64 {
	if t.spans == nil {
		return 0
	}
	return t.spans.Dropped()
}

// Shutdown flushes and stops the providers.
func (t *Telemetry) Shutdown(ctx context.Context) error {
	var errs []error
	if t.tracer != nil {
		errs = append(errs, t.tracer.Shutdown(ctx))
	}
	if t.meter != nil {
		errs = append(errs, t.meter.Shutdown(ctx))
	}
	return errors.Join(errs...)
}

var errorHandlerOnce sync.Once

// Setup installs the global tracer and meter providers cfg asks for. With
// no endpoint and no metrics it installs nothing: every instrument and
// span stays a no-op.
func Setup(cfg Config) (*Telemetry, error) {
	t := &Telemetry{}
	if cfg.Endpoint == "" && !cfg.Metrics {
		return t, nil
	}
	if cfg.Endpoint != "" {
		if err := CheckEndpoint(cfg.Endpoint); err != nil {
			return nil, err
		}
	}
	if cfg.Logger != nil {
		log := cfg.Logger
		errorHandlerOnce.Do(func() {
			otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
				log.Warn("telemetry.error", pclog.Err(err))
			}))
		})
	}
	res := resourceOf(cfg.ServiceName, cfg.ServiceVersion)
	opts := []sdkmetric.Option{sdkmetric.WithView(sdkmetric.NewView(
		sdkmetric.Instrument{Name: "*"}, sdkmetric.Stream{AttributeFilter: Filter}))}
	var c *client
	if cfg.Endpoint != "" {
		c = newClient(strings.TrimSuffix(cfg.Endpoint, "/"), cfg.Headers)
		t.metrics = &metricExporter{c: c, resource: res}
		opts = append(opts, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(t.metrics,
			sdkmetric.WithInterval(MetricInterval), sdkmetric.WithTimeout(ExportTimeout))))
	}
	if cfg.Metrics {
		t.reader = sdkmetric.NewManualReader()
		opts = append(opts, sdkmetric.WithReader(t.reader))
	}
	t.meter = sdkmetric.NewMeterProvider(opts...)
	if c != nil {
		ratio := cfg.SampleRatio
		if ratio < 0 || ratio > 1 {
			return nil, errors.New("telemetry: the sample ratio must be 0..1")
		}
		t.spans = newSpanQueue(&traceExporter{c: c, resource: res}, ratio)
		// Every span is recorded; the queue keeps the sampled ones and every
		// span that ended with an error (G0 M13 D30).
		t.tracer = sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(t.spans))
		otel.SetTracerProvider(t.tracer)
	}
	if err := registerObservables(t.meter.Meter(meterScope), t.DroppedSpans, func() int64 {
		if t.metrics == nil {
			return 0
		}
		return t.metrics.failed.Load()
	}); err != nil {
		return nil, err
	}
	otel.SetMeterProvider(t.meter)
	return t, nil
}

// CheckEndpoint checks telemetry.otlp.endpoint: an absolute http(s) URL
// without query, fragment or user information; https unless the host is
// a loopback IP address or localhost (the local observability profile).
func CheckEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.Opaque != "" {
		return errors.New("telemetry.otlp.endpoint must be an absolute URL without query, fragment or credentials (they go in headers_file)")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if h := u.Hostname(); h == "localhost" {
			return nil
		} else if a, err := netip.ParseAddr(h); err == nil && a.IsLoopback() {
			return nil
		}
	}
	return errors.New("telemetry.otlp.endpoint must use https unless the host is loopback")
}

// ParseHeaders reads a headers file: one "Name: value" per line; blank
// lines and lines starting with # are skipped. For Grafana Cloud:
// "Authorization: Basic <base64 of instance id:token>".
func ParseHeaders(content []byte) ([]Header, error) {
	var out []Header
	sc := bufio.NewScanner(bytes.NewReader(content))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || !validHeaderName(name) || !validHeaderValue(value) {
			// Never echo the line: it may hold a credential.
			return nil, fmt.Errorf("telemetry.otlp.headers_file: line %d is not \"Name: value\"", n)
		}
		out = append(out, Header{Name: name, Value: pclog.NewSecret(value)})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("telemetry.otlp.headers_file: %w", err)
	}
	return out, nil
}

// validHeaderName reports whether s is an HTTP field name (RFC 9110 token).
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return true
}

// validHeaderValue reports whether s is a non-empty field value without
// control characters.
func validHeaderValue(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < 0x20 && r != '\t') || r == 0x7f {
			return false
		}
	}
	return true
}

// LogAttrs returns the trace_id and span_id of ctx's span for log records
// (pclog.Options.ContextAttrs); nothing when ctx has no valid span.
func LogAttrs(ctx context.Context) []slog.Attr {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return nil
	}
	return []slog.Attr{slog.String(pclog.KeyTraceID, sc.TraceID().String()), slog.String(pclog.KeySpanID, sc.SpanID().String())}
}

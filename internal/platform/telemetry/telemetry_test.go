// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package telemetry

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"

	metricsv1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/metrics/v1"
	tracev1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/trace/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// blockingSink never returns until released.
type blockingSink struct {
	release chan struct{}
	calls   atomic.Int64
}

func (b *blockingSink) exportSpans(context.Context, []sdktrace.ReadOnlySpan) error {
	b.calls.Add(1)
	<-b.release
	return nil
}

type failingSink struct{ calls atomic.Int64 }

func (f *failingSink) exportSpans(context.Context, []sdktrace.ReadOnlySpan) error {
	f.calls.Add(1)
	return errors.New("down")
}

func endedSpans(t *testing.T, n int, status codes.Code) []sdktrace.ReadOnlySpan {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	for range n {
		_, s := tp.Tracer("t").Start(context.Background(), "op")
		s.SetStatus(status, "")
		s.End()
	}
	return rec.Ended()
}

// TestHR381_ExporterNeverBlocksARequest ends many spans while the export
// hangs: OnEnd returns at once every time, the queue holds at most 2048
// spans, and every span beyond what the queue and the stuck batch hold is
// dropped and counted.
func TestHR381_ExporterNeverBlocksARequest(t *testing.T) {
	t.Parallel()
	sink := &blockingSink{release: make(chan struct{})}
	q := newSpanQueue(sink, 1)
	spans := endedSpans(t, 10000, codes.Unset)
	start := time.Now()
	for _, s := range spans {
		q.OnEnd(s)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("ending 10000 spans took %v with a stuck exporter", d)
	}
	// The worker holds at most one batch; the queue at most 2048.
	if min := int64(10000 - SpanQueueSize - SpanBatchSize); q.Dropped() < min {
		t.Fatalf("dropped %d, want at least %d", q.Dropped(), min)
	}
	close(sink.release)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := q.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestHR381_FailedExportIsDroppedAndCounted checks a failed export drops
// its batch and counts it, and that sampling keeps error spans.
func TestHR381_FailedExportIsDroppedAndCounted(t *testing.T) {
	t.Parallel()
	sink := &failingSink{}
	q := newSpanQueue(sink, 0) // keep only error spans
	for _, s := range endedSpans(t, 10, codes.Unset) {
		q.OnEnd(s)
	}
	for _, s := range endedSpans(t, 3, codes.Error) {
		q.OnEnd(s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := q.ForceFlush(ctx); err != nil {
		t.Fatal(err)
	}
	if q.Dropped() != 3 || sink.calls.Load() != 1 {
		t.Fatalf("dropped %d after %d exports, want 3 after 1", q.Dropped(), sink.calls.Load())
	}
	_ = q.Shutdown(ctx)
}

func TestSampleRatioKeepsWholeTraces(t *testing.T) {
	t.Parallel()
	q := &spanQueue{ratio: ratioBound(0.5)}
	kept := 0
	spans := endedSpans(t, 2000, codes.Unset)
	for _, s := range spans {
		if q.keep(s) {
			kept++
		}
	}
	if kept < 800 || kept > 1200 {
		t.Fatalf("kept %d of 2000 at ratio 0.5", kept)
	}
	if (&spanQueue{ratio: ratioBound(1)}).keep(spans[0]) != true || (&spanQueue{ratio: ratioBound(0)}).keep(spans[0]) {
		t.Fatal("ratio 1 must keep and ratio 0 must drop a span without an error")
	}
}

// collector is a fake OTLP/HTTP receiver.
type collector struct {
	mu      sync.Mutex
	traces  []*tracev1.TracesData
	metrics []*metricsv1.MetricsData
	auth    []string
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/x-protobuf" || r.Header.Get("Content-Encoding") != "gzip" {
		http.Error(w, "bad content type", http.StatusUnsupportedMediaType)
		return
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		http.Error(w, "gzip", http.StatusBadRequest)
		return
	}
	raw, _ := io.ReadAll(zr)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.auth = append(c.auth, r.Header.Get("Authorization"))
	switch r.URL.Path {
	case "/otlp/v1/traces":
		m := &tracev1.TracesData{}
		if proto.Unmarshal(raw, m) != nil {
			http.Error(w, "proto", http.StatusBadRequest)
			return
		}
		c.traces = append(c.traces, m)
	case "/otlp/v1/metrics":
		m := &metricsv1.MetricsData{}
		if proto.Unmarshal(raw, m) != nil {
			http.Error(w, "proto", http.StatusBadRequest)
			return
		}
		c.metrics = append(c.metrics, m)
	default:
		http.NotFound(w, r)
	}
}

func TestExportersPostOTLPProtobuf(t *testing.T) {
	t.Parallel()
	col := &collector{}
	srv := httptest.NewServer(col)
	defer srv.Close()
	headers, err := ParseHeaders([]byte("# Grafana Cloud\nAuthorization: Basic dGVzdDp0ZXN0\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(srv.URL+"/otlp", headers)
	ctx := context.Background()
	te := &traceExporter{c: c, resource: resourceOf("pantherclaw-server", "test")}
	if err := te.exportSpans(ctx, endedSpans(t, 2, codes.Error)); err != nil {
		t.Fatal(err)
	}
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	h, _ := mp.Meter("t").Float64Histogram(MetricRPCDuration)
	h.Record(ctx, 0.02)
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	me := &metricExporter{c: c, resource: resourceOf("pantherclaw-server", "test")}
	if err := me.Export(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	col.mu.Lock()
	defer col.mu.Unlock()
	if len(col.traces) != 1 || len(col.traces[0].ResourceSpans[0].ScopeSpans[0].Spans) != 2 {
		t.Fatalf("traces = %v", col.traces)
	}
	if got := col.traces[0].ResourceSpans[0].ScopeSpans[0].Spans[0].Status.Code; got != tracev1.Status_STATUS_CODE_ERROR {
		t.Fatalf("status = %v", got)
	}
	if len(col.metrics) != 1 || col.metrics[0].ResourceMetrics[0].ScopeMetrics[0].Metrics[0].GetHistogram().DataPoints[0].Count != 1 {
		t.Fatalf("metrics = %v", col.metrics)
	}
	for _, a := range col.auth {
		if a != "Basic dGVzdDp0ZXN0" {
			t.Fatalf("authorization header = %q", a)
		}
	}
	// A refused export fails by its status and is counted.
	bad := &metricExporter{c: newClient(srv.URL+"/nowhere", nil), resource: resourceOf("s", "")}
	if err := bad.Export(ctx, &rm); !errors.Is(err, errExport) || bad.failed.Load() != 1 {
		t.Fatalf("err = %v, failed = %d", err, bad.failed.Load())
	}
}

func TestParseHeadersNeverEchoesALine(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"Authorization Basic s3cret", "Bad Name: x", "X-Ok: \x01s3cret", "X-Empty:"} {
		_, err := ParseHeaders([]byte(bad))
		if err == nil || strings.Contains(err.Error(), "s3cret") {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	h, err := ParseHeaders([]byte("X-Scope-OrgID: 123\n"))
	if err != nil || len(h) != 1 || h[0].Name != "X-Scope-OrgID" || h[0].Value.Reveal() != "123" {
		t.Fatalf("headers = %v, %v", h, err)
	}
}

func TestCheckEndpoint(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"https://otlp-gateway-prod-eu-west-2.grafana.net/otlp", "http://127.0.0.1:4318", "http://localhost:4318"} {
		if err := CheckEndpoint(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://collector:4318", "https://u:p@host", "https://host?x=1", "otlp:4318", ""} {
		if err := CheckEndpoint(bad); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

// TestHR382_AdminListenerIsLoopbackOnly checks the admin address rules and
// that the listener binds loopback only.
func TestHR382_AdminListenerIsLoopbackOnly(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"0.0.0.0:6060", ":6060", "[::]:6060", "10.0.0.5:6060", "192.168.1.2:6060", "localhost:6060",
		"pantherclaw.example.com:6060", "127.0.0.1", "[fe80::1%eth0]:6060",
	} {
		if err := CheckAdminAddr(bad); !errors.Is(err, ErrAdminNotLoopback) {
			t.Errorf("%q: err = %v", bad, err)
		}
		if _, err := ListenAdmin(context.Background(), bad); err == nil {
			t.Errorf("%q: listened", bad)
		}
	}
	for _, ok := range []string{"", "127.0.0.1:6060", "[::1]:6060", "127.0.0.2:0"} {
		if err := CheckAdminAddr(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	ln, err := ListenAdmin(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if !ln.Addr().(*net.TCPAddr).IP.IsLoopback() {
		t.Fatalf("bound %v", ln.Addr())
	}
}

// TestHR382_AdminHandlerServesProfilesAndMetrics checks the endpoints and
// that nothing is registered on http.DefaultServeMux.
func TestHR382_AdminHandlerServesProfilesAndMetrics(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	g, _ := mp.Meter("t").Int64Gauge(MetricMaintenanceHold)
	g.Record(context.Background(), 1)
	srv := httptest.NewServer(AdminHandler(reader))
	defer srv.Close()
	for path, want := range map[string]string{
		"/metrics":                       "pc_maintenance_hold 1",
		"/debug/pprof/goroutine?debug=1": "goroutine profile",
		"/debug/pprof/heap":              "",
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(want)) {
			t.Errorf("%s: %d %q", path, resp.StatusCode, body)
		}
	}
	if _, pattern := http.DefaultServeMux.Handler(httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)); pattern != "" {
		t.Fatalf("DefaultServeMux serves %q", pattern)
	}
}

func TestQueryName(t *testing.T) {
	t.Parallel()
	for sql, want := range map[string]string{
		"-- name: GetLedgerHead :one\nSELECT 1":       "GetLedgerHead",
		"\n-- name: InsertX :exec\nINSERT":            "InsertX",
		"SELECT secret FROM t WHERE email = 'a@b.c'":  "sql",
		"-- name: Bad;DROP :one":                      "sql",
		"-- name: " + strings.Repeat("A", 65) + " :x": "sql",
	} {
		if got := QueryName(sql); got != want {
			t.Errorf("QueryName(%q) = %q, want %q", sql, got, want)
		}
	}
}

func TestLogAttrsAddTraceIDs(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := pclog.New(&buf, pclog.Options{ContextAttrs: []func(context.Context) []slog.Attr{LogAttrs}})
	tp := sdktrace.NewTracerProvider()
	ctx, span := tp.Tracer("t").Start(context.Background(), "op")
	log.InfoContext(ctx, "in.span")
	log.InfoContext(context.Background(), "no.span")
	span.End()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	sc := trace.SpanContextFromContext(ctx)
	if !strings.Contains(lines[0], `"trace_id":"`+sc.TraceID().String()+`"`) || !strings.Contains(lines[0], `"span_id":"`+sc.SpanID().String()+`"`) {
		t.Fatalf("in span: %s", lines[0])
	}
	if strings.Contains(lines[1], "trace_id") {
		t.Fatalf("no span: %s", lines[1])
	}
}

func TestSetupOffInstallsNothing(t *testing.T) {
	t.Parallel()
	tel, err := Setup(Config{})
	if err != nil || tel.Enabled() || tel.Reader() != nil {
		t.Fatalf("Setup(off) = %+v, %v", tel, err)
	}
}

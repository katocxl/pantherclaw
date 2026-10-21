// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package telemetry

import (
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	commonv1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/common/v1"
	resourcev1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/resource/v1"
	tracev1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/trace/v1"
)

// The span queue's bounds (G0 M13 D30, HR-381).
const (
	SpanQueueSize = 2048
	SpanBatchSize = 512
	SpanBatchWait = 5 * time.Second
)

// spanSink exports one batch of spans.
type spanSink interface {
	exportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error
}

// spanQueue is the span processor between the SDK and the exporter. It
// never blocks the request that ends a span (HR-381): a span goes into a
// bounded queue with a non-blocking send, or is dropped and counted when
// the queue is full; a failed export drops its batch and counts it. One
// goroutine exports batches of at most 512 spans, at least every 5 s.
//
// It also samples (G0 M13 D30): a span whose trace id falls under the
// ratio is kept, and so is every span that ended with an error.
type spanQueue struct {
	sink    spanSink
	ratio   uint64 // spans whose trace id's low 63 bits are below it are kept
	queue   chan sdktrace.ReadOnlySpan
	dropped atomic.Int64
	flush   chan chan struct{}
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
}

func newSpanQueue(sink spanSink, sampleRatio float64) *spanQueue {
	q := &spanQueue{
		sink: sink, ratio: ratioBound(sampleRatio),
		queue: make(chan sdktrace.ReadOnlySpan, SpanQueueSize),
		flush: make(chan chan struct{}), stop: make(chan struct{}), done: make(chan struct{}),
	}
	go q.run()
	return q
}

// ratioBound is the trace id bound of a sample ratio, as the SDK's
// TraceIDRatioBased sampler computes it, so a trace is kept or not as a
// whole.
func ratioBound(r float64) uint64 {
	switch {
	case r >= 1:
		return 1 << 63
	case r <= 0:
		return 0
	default:
		return uint64(r * (1 << 63))
	}
}

func (q *spanQueue) keep(s sdktrace.ReadOnlySpan) bool {
	if s.Status().Code == codes.Error {
		return true
	}
	id := s.SpanContext().TraceID()
	return binary.BigEndian.Uint64(id[8:16])>>1 < q.ratio
}

// OnStart implements sdktrace.SpanProcessor.
func (q *spanQueue) OnStart(context.Context, sdktrace.ReadWriteSpan) {}

// OnEnd implements sdktrace.SpanProcessor: it never blocks.
func (q *spanQueue) OnEnd(s sdktrace.ReadOnlySpan) {
	if !q.keep(s) {
		return
	}
	select {
	case q.queue <- s:
	default:
		q.dropped.Add(1)
	}
}

// Dropped is the number of spans dropped so far: queue overflow plus
// failed exports.
func (q *spanQueue) Dropped() int64 { return q.dropped.Load() }

// ForceFlush exports what is queued now.
func (q *spanQueue) ForceFlush(ctx context.Context) error {
	ack := make(chan struct{})
	select {
	case q.flush <- ack:
	case <-q.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-ack:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Shutdown exports what is queued and stops.
func (q *spanQueue) Shutdown(ctx context.Context) error {
	q.once.Do(func() { close(q.stop) })
	select {
	case <-q.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (q *spanQueue) run() {
	defer close(q.done)
	batch := make([]sdktrace.ReadOnlySpan, 0, SpanBatchSize)
	timer := time.NewTimer(SpanBatchWait)
	defer timer.Stop()
	export := func() {
		if len(batch) == 0 {
			return
		}
		if err := q.sink.exportSpans(context.Background(), batch); err != nil {
			q.dropped.Add(int64(len(batch)))
		}
		batch = batch[:0]
	}
	drain := func() {
		for {
			select {
			case s := <-q.queue:
				batch = append(batch, s)
				if len(batch) == SpanBatchSize {
					export()
				}
			default:
				export()
				return
			}
		}
	}
	for {
		select {
		case s := <-q.queue:
			batch = append(batch, s)
			if len(batch) == SpanBatchSize {
				export()
			}
		case <-timer.C:
			export()
			timer.Reset(SpanBatchWait)
		case ack := <-q.flush:
			drain()
			close(ack)
		case <-q.stop:
			drain()
			return
		}
	}
}

// traceExporter posts spans as OTLP TracesData.
type traceExporter struct {
	c        *client
	resource *resourcev1.Resource
}

func (e *traceExporter) exportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	return e.c.post(ctx, tracesPath, tracesData(e.resource, spans))
}

// tracesData converts spans: names, ids, kinds, times, the allow-listed
// attributes (HR-380) and the status code. Status messages, events and
// links are never exported (they could carry error text).
func tracesData(res *resourcev1.Resource, spans []sdktrace.ReadOnlySpan) *tracev1.TracesData {
	byScope := map[string]*tracev1.ScopeSpans{}
	var scopes []*tracev1.ScopeSpans
	for _, s := range spans {
		name := s.InstrumentationScope().Name
		ss, ok := byScope[name]
		if !ok {
			ss = &tracev1.ScopeSpans{Scope: &commonv1.InstrumentationScope{Name: name}}
			byScope[name] = ss
			scopes = append(scopes, ss)
		}
		sc := s.SpanContext()
		tid, sid := sc.TraceID(), sc.SpanID()
		out := &tracev1.Span{
			TraceId: tid[:], SpanId: sid[:], Name: s.Name(), Kind: spanKind(s.SpanKind()),
			StartTimeUnixNano: unixNano(s.StartTime()), EndTimeUnixNano: unixNano(s.EndTime()),
			Attributes: keyValues(s.Attributes()), Status: &tracev1.Status{Code: statusCode(s.Status().Code)},
		}
		if p := s.Parent(); p.IsValid() {
			psid := p.SpanID()
			out.ParentSpanId = psid[:]
		}
		ss.Spans = append(ss.Spans, out)
	}
	return &tracev1.TracesData{ResourceSpans: []*tracev1.ResourceSpans{{Resource: res, ScopeSpans: scopes}}}
}

func spanKind(k trace.SpanKind) tracev1.Span_SpanKind {
	switch k {
	case trace.SpanKindInternal:
		return tracev1.Span_SPAN_KIND_INTERNAL
	case trace.SpanKindServer:
		return tracev1.Span_SPAN_KIND_SERVER
	case trace.SpanKindClient:
		return tracev1.Span_SPAN_KIND_CLIENT
	case trace.SpanKindProducer:
		return tracev1.Span_SPAN_KIND_PRODUCER
	case trace.SpanKindConsumer:
		return tracev1.Span_SPAN_KIND_CONSUMER
	default:
		return tracev1.Span_SPAN_KIND_UNSPECIFIED
	}
}

func statusCode(c codes.Code) tracev1.Status_StatusCode {
	switch c {
	case codes.Ok:
		return tracev1.Status_STATUS_CODE_OK
	case codes.Error:
		return tracev1.Status_STATUS_CODE_ERROR
	default:
		return tracev1.Status_STATUS_CODE_UNSET
	}
}

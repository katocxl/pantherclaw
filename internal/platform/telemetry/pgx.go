// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package telemetry

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// QueryTracer is the pgx tracer (G0 M13 D30): one client span per query,
// named by its sqlc query name ("-- name: GetX :one") only, or "sql" for a
// query written by hand. The SQL text and its arguments never become a
// span name or attribute (HR-380).
type QueryTracer struct {
	tracer trace.Tracer
}

// NewQueryTracer returns a tracer on the global tracer provider.
func NewQueryTracer() *QueryTracer {
	return &QueryTracer{tracer: otel.Tracer("github.com/katocxl/pantherclaw/internal/platform/db")}
}

var _ pgx.QueryTracer = (*QueryTracer)(nil)

// TraceQueryStart implements pgx.QueryTracer.
func (t *QueryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !trace.SpanContextFromContext(ctx).IsValid() {
		// Only queries inside a traced request or job get a span; pool
		// housekeeping (RESET ALL, session checks) does not start traces.
		return ctx
	}
	ctx, span := t.tracer.Start(ctx, QueryName(data.SQL), trace.WithSpanKind(trace.SpanKindClient))
	return context.WithValue(ctx, querySpanKey{}, span)
}

// querySpanKey holds the query's own span, so the end never ends the
// caller's span when the start made none.
type querySpanKey struct{}

// TraceQueryEnd implements pgx.QueryTracer.
func (t *QueryTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	span, ok := ctx.Value(querySpanKey{}).(trace.Span)
	if !ok {
		return
	}
	if data.Err != nil {
		span.SetStatus(codes.Error, "")
	}
	span.End()
}

// QueryName returns the sqlc name of a query ("-- name: GetX :one" on its
// first line), or "sql".
func QueryName(sql string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(sql), "\n")
	rest, ok := strings.CutPrefix(line, "-- name: ")
	if !ok {
		return "sql"
	}
	name, _, _ := strings.Cut(rest, " ")
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return "sql"
		}
	}
	if name == "" || len(name) > 64 {
		return "sql"
	}
	return name
}

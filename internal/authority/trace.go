// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// The agent's W3C trace context (G0 M36 D1060, HR-785). The gateway sends
// it beside the action; the Authority carries it to the new transaction's
// row and nowhere else. No check reads it: it is not part of the ActionIR,
// a digest, a receipt, a recording or a binding, so an action is decided
// the same with or without it.

type traceKey struct{}

// withTrace notes the request's trace context for the pipeline request; a
// missing or malformed one is ignored.
func withTrace(ctx context.Context, tc *pantherclawv1.TraceContext) context.Context {
	if t := traceOf(tc); t != nil {
		return context.WithValue(ctx, traceKey{}, t)
	}
	return ctx
}

// traceFrom is the trace context withTrace noted; nil when none.
func traceFrom(ctx context.Context) *pipeline.TraceContext {
	t, _ := ctx.Value(traceKey{}).(*pipeline.TraceContext)
	return t
}

// traceOf converts a trace context, refusing (nil) anything but a 16-byte
// trace id that is not all zero, an 8-byte parent span id that is not all
// zero and a flags byte.
func traceOf(tc *pantherclawv1.TraceContext) *pipeline.TraceContext {
	if tc == nil || len(tc.GetTraceId()) != 16 || len(tc.GetParentSpanId()) != 8 || tc.GetFlags() > 255 {
		return nil
	}
	var out pipeline.TraceContext
	copy(out.TraceID[:], tc.GetTraceId())
	copy(out.ParentSpanID[:], tc.GetParentSpanId())
	if out.TraceID == ([16]byte{}) || out.ParentSpanID == ([8]byte{}) {
		return nil
	}
	out.Flags = uint8(tc.GetFlags()) //nolint:gosec // G115: checked ≤ 255 above
	return &out
}

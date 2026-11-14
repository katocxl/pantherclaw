// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"bytes"
	"context"
	"testing"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestHR785_OnlyAStrictTraceContextIsStored: the Authority keeps a 16-byte
// trace id and an 8-byte parent span id, and drops an all-zero or oversized
// one before it can be written on the transaction.
// Covers: HR-785
func TestHR785_OnlyAStrictTraceContextIsStored(t *testing.T) {
	id := bytes.Repeat([]byte{0xab}, 16)
	span := bytes.Repeat([]byte{0xcd}, 8)
	got := traceOf(&pantherclawv1.TraceContext{TraceId: id, ParentSpanId: span, Flags: 1})
	if got == nil || got.Flags != 1 || got.TraceID != [16]byte(id) {
		t.Fatalf("strict context: %+v", got)
	}
	ctx := withTrace(context.Background(), &pantherclawv1.TraceContext{TraceId: id, ParentSpanId: span, Flags: 1})
	if traceFrom(ctx) == nil {
		t.Fatal("a strict context was dropped")
	}

	for _, tc := range []*pantherclawv1.TraceContext{
		{TraceId: make([]byte, 16), ParentSpanId: span},
		{TraceId: id, ParentSpanId: make([]byte, 8)},
		{TraceId: id[:15], ParentSpanId: span},
		{TraceId: id, ParentSpanId: span, Flags: 256},
		nil,
	} {
		if traceOf(tc) != nil {
			t.Errorf("stored %+v", tc)
		}
		if traceFrom(withTrace(context.Background(), tc)) != nil {
			t.Errorf("context kept %+v", tc)
		}
	}
}

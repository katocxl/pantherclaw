// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"encoding/hex"
	"strings"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// The agent's W3C Trace Context (G0 M36 D1060, HR-785). Every face reads
// it, the Authority stores it on the transaction, and the org's OTLP export
// puts the transaction's spans in the agent's trace. It is correlation
// metadata only: it never enters the ActionIR, a digest or a binding, and
// input that does not parse is ignored, never an error.
const (
	HeaderTraceparent = "traceparent"
	HeaderTracestate  = "tracestate"
	// MaxTracestate bounds the tracestate kept.
	MaxTracestate = 512
	// traceparentLen is the length of a version 00 traceparent.
	traceparentLen = 55
)

// ParseTraceContext reads a traceparent (exactly one value) and the
// tracestate values; nil when the traceparent is absent or invalid. A
// tracestate longer than MaxTracestate, or with bytes outside printable
// ASCII, is dropped while the traceparent is kept.
func ParseTraceContext(traceparent, tracestate []string) *pb.TraceContext {
	if len(traceparent) != 1 {
		return nil
	}
	tc := ParseTraceparent(traceparent[0])
	if tc == nil {
		return nil
	}
	if state := strings.Join(tracestate, ","); validTracestate(state) {
		tc.Tracestate = state
	}
	return tc
}

// ParseTraceparent parses a version 00 traceparent strictly: 00, a 32-hex
// trace id that is not all zero, a 16-hex parent span id that is not all
// zero and 2-hex flags, lowercase, separated by dashes. Anything else is
// nil.
func ParseTraceparent(v string) *pb.TraceContext {
	if len(v) != traceparentLen || v[2] != '-' || v[35] != '-' || v[52] != '-' || v[:2] != "00" {
		return nil
	}
	traceID, ok := lowerHex(v[3:35])
	if !ok || allZero(traceID) {
		return nil
	}
	span, ok := lowerHex(v[36:52])
	if !ok || allZero(span) {
		return nil
	}
	flags, ok := lowerHex(v[53:55])
	if !ok {
		return nil
	}
	return &pb.TraceContext{TraceId: traceID, ParentSpanId: span, Flags: uint32(flags[0])}
}

// TraceFromMeta reads an MCP request's params._meta traceparent and
// tracestate, already decoded as strings by the face; nil when absent or
// invalid.
func TraceFromMeta(traceparent, tracestate string, ok bool) *pb.TraceContext {
	if !ok {
		return nil
	}
	tc := ParseTraceparent(traceparent)
	if tc != nil && validTracestate(tracestate) {
		tc.Tracestate = tracestate
	}
	return tc
}

func lowerHex(s string) ([]byte, bool) {
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, false
		}
	}
	b, err := hex.DecodeString(s)
	return b, err == nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func validTracestate(s string) bool {
	if s == "" || len(s) > MaxTracestate {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

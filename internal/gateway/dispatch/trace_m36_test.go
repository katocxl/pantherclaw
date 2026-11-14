// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"bytes"
	"encoding/json/jsontext"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
)

const validTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

// TestHR785_TraceparentIsStrictAndStaysOutOfTheAction: a version-00
// traceparent is kept, and anything else is ignored. The parsed context is
// not part of the ActionIR, so it cannot change the action hash.
// Covers: HR-785
func TestHR785_TraceparentIsStrictAndStaysOutOfTheAction(t *testing.T) {
	got := ParseTraceparent(validTraceparent)
	if got == nil || len(got.GetTraceId()) != 16 || len(got.GetParentSpanId()) != 8 || got.GetFlags() != 1 {
		t.Fatalf("valid traceparent: %+v", got)
	}
	state := ParseTraceContext([]string{validTraceparent}, []string{"vendor=one"})
	if state == nil || state.GetTracestate() != "vendor=one" {
		t.Fatalf("tracestate: %+v", state)
	}
	// A tracestate over 512 bytes is dropped; the traceparent is kept.
	long := ParseTraceContext([]string{validTraceparent}, []string{strings.Repeat("a", MaxTracestate+1)})
	if long == nil || long.GetTracestate() != "" {
		t.Fatalf("over-long tracestate: %+v", long)
	}

	for _, bad := range []string{
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		validTraceparent + " ",
	} {
		if ParseTraceparent(bad) != nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if ParseTraceContext([]string{validTraceparent, validTraceparent}, nil) != nil {
		t.Fatal("two traceparent values were accepted")
	}
	if ParseTraceContext(nil, []string{"vendor=one"}) != nil {
		t.Fatal("tracestate alone was accepted")
	}
	if TraceFromMeta("not-a-trace", "vendor=one", true) != nil {
		t.Fatal("MCP _meta accepted a forged traceparent")
	}

	p, err := actionir.Encode(m36Action())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(p.Canonical, []byte("trace")) {
		t.Fatalf("action canonical contains trace: %s", p.Canonical)
	}
	with := pipeline.Request{Action: p, Trace: &pipeline.TraceContext{Flags: 1}}
	without := pipeline.Request{Action: p}
	if with.Action.Hash != without.Action.Hash {
		t.Fatal("a trace context changed the action hash")
	}
}

// TestT355_AForgedTraceHeaderDoesNotChangeCorrelationOrTheAction: an
// all-zero or upper-case traceparent is ignored, and a real one still does
// not enter the action digest.
// Covers: T-355
func TestT355_AForgedTraceHeaderDoesNotChangeCorrelationOrTheAction(t *testing.T) {
	forged := "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
	if ParseTraceContext([]string{forged}, []string{"vendor=attacker"}) != nil {
		t.Fatal("all-zero trace id was stored")
	}
	p, err := actionir.Encode(m36Action())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.ToLower(p.Canonical), []byte(forged)) || bytes.Contains(p.Canonical, []byte("traceparent")) {
		t.Fatalf("forged header is in the action: %s", p.Canonical)
	}
}

func m36Action() actionir.ActionIR {
	return actionir.ActionIR{
		V: 1, Org: "01920000-0000-7000-8000-00000000000a", Env: "01920000-0000-7000-8000-00000000000e",
		RunID: "01920000-0000-7000-8000-0000000000a1", ActionID: "01920000-0000-7000-8000-0000000000b1",
		AgentInstance: "01920000-0000-7000-8000-0000000000c1",
		Operation:     actionir.OpRefundCreate,
		Definition:    actionir.Definition{Package: "pc.mock-payments", Version: "1.0.0", Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000001"},
		Channel:       "http", Route: "payments-refund",
		Target:    actionir.Target{Type: "payments.charge", ID: "ch_3Px001", Account: "acct_001"},
		Params:    jsontext.Value(`{"amount":{"value":"30.00","currency":"USD"},"reason":"duplicate"}`),
		DedupeKey: "refund:ch_3Px001",
	}
}

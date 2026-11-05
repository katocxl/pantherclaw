// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package otlpexport

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	commonv1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/common/v1"
	resourcev1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/resource/v1"
	tracev1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/trace/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Span shapes (G0 M36 D1062; FQ36-2; HR-787, HR-788). A transaction gives a
// decision span and, once dispatched, a tool or model span; its effects are
// events on that span. Spans are in the agent's trace with the agent's span
// as parent when the agent sent a traceparent; otherwise the trace id is
// SHA-256(run id)[:16] and they have no parent. Span ids are
// SHA-256(transaction id + kind)[:8], so exporting a transaction again
// gives the same spans.
//
// Attributes are metadata only: ids, operation, channel, decision and its
// first reason code, coverage, outcome, model and token counts, timings and
// links, and pantherclaw.simulated on every span and event of a simulated
// transaction (D1062a). Never a prompt, argument, answer, approval text or
// target id.

// Span kinds in the span id derivation.
const (
	kindDecide   = "decide"
	kindDispatch = "dispatch"
)

// Span and attribute names.
const (
	spanDecide      = "pantherclaw.decide"
	eventEffect     = "pantherclaw.effect"
	scopeName       = "pantherclaw"
	serviceName     = "pantherclaw"
	opExecuteTool   = "execute_tool"
	opChat          = "chat"
	channelMCP      = "mcp"
	mcpToolsCall    = "tools/call"
	outcomeFailed   = "failed"
	consoleTxnsPath = "/app/evidence/transactions/"
)

// spanEffect is one effect state of a transaction.
type spanEffect struct {
	State string
	At    time.Time
}

// buildTraces turns a batch's transactions into one OTLP TracesData
// message: one resource (the org), one scope.
func buildTraces(org ids.OrgID, consoleURL string, rows []dbq.OTLPSpanTransactionsRow, effects map[ids.UUID][]spanEffect) *tracev1.TracesData {
	spans := make([]*tracev1.Span, 0, 2*len(rows))
	for _, r := range rows {
		spans = append(spans, transactionSpans(consoleURL, r, effects[r.ID])...)
	}
	return &tracev1.TracesData{ResourceSpans: []*tracev1.ResourceSpans{{
		Resource:   resourceOf(org),
		ScopeSpans: []*tracev1.ScopeSpans{{Scope: &commonv1.InstrumentationScope{Name: scopeName}, Spans: spans}},
	}}}
}

// resourceOf is the exported resource: the service and the org.
func resourceOf(org ids.OrgID) *resourcev1.Resource {
	return &resourcev1.Resource{Attributes: []*commonv1.KeyValue{
		str("service.name", serviceName), str("pantherclaw.org_id", org.String()),
	}}
}

// traceOf is the transaction's trace id, parent span id and flags.
func traceOf(r dbq.OTLPSpanTransactionsRow) (traceID, parent []byte, flags uint32) {
	if len(r.TraceID) == 16 && len(r.ParentSpanID) == 8 {
		if r.TraceFlags.Valid {
			flags = uint32(r.TraceFlags.Int16) & 0xff //nolint:gosec // G115: a flags byte (CHECK 0..255)
		}
		return r.TraceID, r.ParentSpanID, flags
	}
	sum := sha256.Sum256(r.RunID[:])
	return sum[:16], nil, 0
}

// spanID derives a span's id from its transaction and kind (HR-788).
func spanID(txn ids.UUID, kind string) []byte {
	sum := sha256.Sum256([]byte(txn.String() + kind))
	return sum[:8]
}

func transactionSpans(consoleURL string, r dbq.OTLPSpanTransactionsRow, effects []spanEffect) []*tracev1.Span {
	traceID, parent, flags := traceOf(r)
	decidedAt := r.DecidedAt
	if decidedAt.Before(r.CreatedAt) {
		decidedAt = r.CreatedAt
	}
	attrs := []*commonv1.KeyValue{
		str("pantherclaw.decision", r.Decision),
		str("pantherclaw.reason_code", r.ReasonCode),
		str("pantherclaw.transaction_id", r.ID.String()),
		str("pantherclaw.run_id", r.RunID.String()),
		str("pantherclaw.agent_id", r.AgentID.String()),
		str("pantherclaw.operation", r.Operation),
	}
	if r.Channel != "" {
		attrs = append(attrs, str("pantherclaw.channel", r.Channel))
	}
	if c := coverageOf(r.ReceiptJws); c != "" {
		attrs = append(attrs, str("pantherclaw.coverage", c))
	}
	if r.Simulated {
		attrs = append(attrs, simulated())
	}
	if consoleURL != "" {
		attrs = append(attrs, str("pantherclaw.console_url", strings.TrimSuffix(consoleURL, "/")+consoleTxnsPath+r.ID.String()))
	}
	out := []*tracev1.Span{{
		TraceId: traceID, SpanId: spanID(r.ID, kindDecide), ParentSpanId: parent, Flags: flags,
		Name: spanDecide, Kind: tracev1.Span_SPAN_KIND_INTERNAL,
		StartTimeUnixNano: unixNano(r.CreatedAt), EndTimeUnixNano: unixNano(decidedAt), Attributes: attrs,
	}}
	if r.DispatchOutcome == "" {
		return out
	}
	end := r.DispatchedAt
	start := end
	if r.DispatchMs != nil && *r.DispatchMs > 0 {
		start = end.Add(-time.Duration(*r.DispatchMs) * time.Millisecond)
	}
	d := &tracev1.Span{
		TraceId: traceID, SpanId: spanID(r.ID, kindDispatch), ParentSpanId: parent, Flags: flags,
		Kind: tracev1.Span_SPAN_KIND_CLIENT, StartTimeUnixNano: unixNano(start), EndTimeUnixNano: unixNano(end),
	}
	if r.Model != nil {
		// A model call (G0 M29): the GenAI chat span.
		d.Name = strings.TrimSpace(opChat + " " + *r.Model)
		d.Attributes = []*commonv1.KeyValue{
			str("gen_ai.operation.name", opChat),
			str("gen_ai.provider.name", providerOf(r.Operation)),
			str("gen_ai.request.model", *r.Model),
			num("gen_ai.usage.input_tokens", r.InputTokens),
			num("gen_ai.usage.output_tokens", r.OutputTokens),
		}
	} else {
		d.Name = opExecuteTool + " " + r.Operation
		d.Attributes = []*commonv1.KeyValue{
			str("gen_ai.operation.name", opExecuteTool),
			str("gen_ai.tool.name", r.Operation),
		}
		if r.Channel == channelMCP {
			d.Attributes = append(d.Attributes, str("mcp.method.name", mcpToolsCall))
		}
	}
	d.Attributes = append(d.Attributes, str("pantherclaw.outcome", r.DispatchOutcome), str("pantherclaw.transaction_id", r.ID.String()))
	if r.Simulated {
		d.Attributes = append(d.Attributes, simulated())
	}
	if r.DispatchOutcome == outcomeFailed {
		d.Status = &tracev1.Status{Code: tracev1.Status_STATUS_CODE_ERROR}
	}
	for _, e := range effects {
		ev := []*commonv1.KeyValue{str("state", e.State)}
		if r.Simulated {
			ev = append(ev, simulated())
		}
		d.Events = append(d.Events, &tracev1.Span_Event{
			TimeUnixNano: unixNano(e.At), Name: eventEffect, Attributes: ev,
		})
	}
	return append(out, d)
}

// providers maps a model operation's first segment to its GenAI
// provider name.
var providers = map[string]string{
	"anthropic": "anthropic", "openai": "openai", "bedrock": "aws.bedrock", "vertex": "gcp.vertex_ai",
}

func providerOf(operation string) string {
	first, _, _ := strings.Cut(operation, ".")
	if p, ok := providers[first]; ok {
		return p
	}
	return first
}

// coverageOf reads the coverage state from a decision receipt's claims,
// without verifying it: the span only reports it. "" when there is none.
func coverageOf(jws string) string {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		PAP struct {
			Coverage *struct {
				State       string `json:"state"`
				Unavailable string `json:"unavailable"`
			} `json:"coverage"`
		} `json:"pap"`
	}
	if json.Unmarshal(payload, &c) != nil || c.PAP.Coverage == nil {
		return ""
	}
	if c.PAP.Coverage.Unavailable != "" {
		return "UNAVAILABLE"
	}
	return c.PAP.Coverage.State
}

// testTraces is the one span a destination test sends: no agent data.
func testTraces(org ids.OrgID, now time.Time) *tracev1.TracesData {
	traceID := make([]byte, 16)
	spanID := make([]byte, 8)
	_, _ = rand.Read(traceID)
	_, _ = rand.Read(spanID)
	return &tracev1.TracesData{ResourceSpans: []*tracev1.ResourceSpans{{
		Resource: resourceOf(org),
		ScopeSpans: []*tracev1.ScopeSpans{{Scope: &commonv1.InstrumentationScope{Name: scopeName}, Spans: []*tracev1.Span{{
			TraceId: traceID, SpanId: spanID, Name: "pantherclaw.test", Kind: tracev1.Span_SPAN_KIND_INTERNAL,
			StartTimeUnixNano: unixNano(now), EndTimeUnixNano: unixNano(now),
		}}}},
	}}}
}

func str(k, v string) *commonv1.KeyValue {
	return &commonv1.KeyValue{Key: k, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: v}}}
}

// simulated marks a span or span event built from a simulated transaction
// (G0 M36 D1062a); real transactions never carry it.
func simulated() *commonv1.KeyValue {
	return &commonv1.KeyValue{Key: "pantherclaw.simulated", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_BoolValue{BoolValue: true}}}
}

func num(k string, v int64) *commonv1.KeyValue {
	return &commonv1.KeyValue{Key: k, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_IntValue{IntValue: v}}}
}

func unixNano(t time.Time) uint64 {
	if t.IsZero() || t.UnixNano() < 0 {
		return 0
	}
	return uint64(t.UnixNano()) //nolint:gosec // G115: checked non-negative
}

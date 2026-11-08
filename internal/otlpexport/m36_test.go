// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package otlpexport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	commonv1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/common/v1"
	tracev1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/trace/v1"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition struct{ e billing.Edition }

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: e.e}, nil
}

func m36Service(t *testing.T) *Service {
	t.Helper()
	svc, err := New(nil, nil, nil, Config{PublicURL: "https://pantherclaw.example"}, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func securityAdmin(t *testing.T) context.Context {
	t.Helper()
	org := ids.New[ids.Org]()
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{
			Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
			Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
		},
		Credential: tenancy.CredBrowserSession,
	})
}

func publicDest() NewDestination {
	return NewDestination{Name: "traces", URL: "https://collector.example/v1/traces"}
}

// TestHR786_OTLPDestinationsNeedBusinessAndAStepUp: a destination URL
// follows the SIEM rules, header values are not on the returned record,
// activation over the API is refused, and Team (or no licence) cannot
// create or activate one.
// Covers: HR-786, F1061
func TestHR786_OTLPDestinationsNeedBusinessAndAStepUp(t *testing.T) {
	if err := CheckURL("https://collector.example/v1/traces", "pantherclaw.example", nil); err != nil {
		t.Fatalf("public https collector: %v", err)
	}
	for _, raw := range []string{
		"http://collector.example/v1/traces",
		"https://127.0.0.1/v1/traces",
		"https://user:pass@collector.example/v1/traces",
		"https://pantherclaw.example/v1/traces",
	} {
		if err := CheckURL(raw, "pantherclaw.example", nil); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	if err := CheckURL("https://169.254.169.254/latest", "pantherclaw.example", nil); !errors.Is(err, ErrMetadata) {
		t.Fatalf("metadata host: %v", err)
	}
	if err := validHeaders([]Header{{Name: "Host", Value: "collector.example"}}); !errors.Is(err, ErrHeader) {
		t.Fatalf("reserved header: %v", err)
	}
	if err := validHeaders([]Header{{Name: "DD-API-KEY", Value: "present"}}); err != nil {
		t.Fatalf("collector header: %v", err)
	}
	for _, f := range reflect.VisibleFields(reflect.TypeOf(Destination{})) {
		name := strings.ToLower(f.Name)
		if strings.Contains(name, "secret") || strings.Contains(name, "value") {
			t.Errorf("destination exposes %s", f.Name)
		}
	}

	for _, ed := range []billing.Edition{billing.Community, billing.Team, ""} {
		svc := m36Service(t).WithEditions(edition{ed})
		if ed == "" {
			svc = m36Service(t) // no licence source
		}
		_, err := svc.Create(securityAdmin(t), publicDest())
		if !errors.Is(err, ErrEdition) {
			t.Errorf("%q create: %v", ed, err)
		}
	}
	svc := m36Service(t).WithEditions(edition{billing.Business})
	_, err := svc.Activate(securityAdmin(t), ids.NewV7(), nil)
	if !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("API activate: %v, want STEP_UP_REQUIRED", err)
	}
	if (billing.Entitlements{Edition: billing.Business}).OTLPExport() != true ||
		(billing.Entitlements{Edition: billing.Enterprise}).OTLPExport() != true ||
		(billing.Entitlements{Edition: billing.Team}).OTLPExport() ||
		(billing.Entitlements{Edition: billing.Community}).OTLPExport() {
		t.Fatal("OTLP export edition line is not Business and above")
	}
}

// TestT356_AnOTLPDestinationCannotBePointedAtAPrivateHost: the exfiltration
// URLs are refused before a destination exists.
// Covers: T-356
func TestT356_AnOTLPDestinationCannotBePointedAtAPrivateHost(t *testing.T) {
	svc := m36Service(t).WithEditions(edition{billing.Business})
	_, err := svc.Create(securityAdmin(t), NewDestination{Name: "traces", URL: "https://10.1.2.3/v1/traces"})
	if !errors.Is(err, ErrURL) && !errors.Is(err, ErrMetadata) {
		t.Fatalf("private collector: %v", err)
	}
}

// TestHR787_SpansCarryMetadataOnly: attribute keys are the closed metadata
// set, a simulated transaction is marked, and the row the exporter reads
// has no prompt, argument, answer or target id.
// Covers: HR-787, D1062a
func TestHR787_SpansCarryMetadataOnly(t *testing.T) {
	for _, f := range reflect.VisibleFields(reflect.TypeOf(dbq.OTLPSpanTransactionsRow{})) {
		n := strings.ToLower(f.Name)
		for _, bad := range []string{"prompt", "argument", "answer", "targetid", "body", "payload"} {
			if strings.Contains(n, bad) {
				t.Errorf("span row has %s", f.Name)
			}
		}
	}
	row := sampleRow(false)
	row.TargetType = "user.email"
	spans := transactionSpans("https://console.example", row, []spanEffect{{State: "confirmed", At: row.DecidedAt}})
	if len(spans) != 2 {
		t.Fatalf("%d spans", len(spans))
	}
	assertKeys(t, "decide", spans[0].GetAttributes(), map[string]bool{
		"pantherclaw.decision": true, "pantherclaw.reason_code": true, "pantherclaw.transaction_id": true,
		"pantherclaw.run_id": true, "pantherclaw.agent_id": true, "pantherclaw.operation": true,
		"pantherclaw.channel": true, "pantherclaw.console_url": true,
	})
	assertKeys(t, "dispatch", spans[1].GetAttributes(), map[string]bool{
		"gen_ai.operation.name": true, "gen_ai.tool.name": true, "mcp.method.name": true,
		"pantherclaw.outcome": true, "pantherclaw.transaction_id": true,
	})
	if spans[1].GetName() != "execute_tool github.pulls.merge" || spans[1].GetAttributes()[0].GetValue().GetStringValue() != "execute_tool" {
		t.Fatalf("tool span: %s", spans[1].GetName())
	}
	blob := spanText(spans)
	if strings.Contains(blob, "user.email") || strings.Contains(blob, "PROMPT") || strings.Contains(blob, "pantherclaw.simulated") {
		t.Fatalf("span leaked or marked a real transaction:\n%s", blob)
	}
	if len(spans[1].GetEvents()) != 1 || spans[1].GetEvents()[0].GetName() != eventEffect {
		t.Fatalf("effect event: %+v", spans[1].GetEvents())
	}

	model := "claude-sonnet"
	row.Model = &model
	row.InputTokens, row.OutputTokens = 11, 7
	row.Channel = "sdk"
	row.Simulated = true
	chat := transactionSpans("", row, []spanEffect{{State: "confirmed", At: row.DecidedAt}})
	assertKeys(t, "chat", chat[1].GetAttributes(), map[string]bool{
		"gen_ai.operation.name": true, "gen_ai.provider.name": true, "gen_ai.request.model": true,
		"gen_ai.usage.input_tokens": true, "gen_ai.usage.output_tokens": true,
		"pantherclaw.outcome": true, "pantherclaw.transaction_id": true, "pantherclaw.simulated": true,
	})
	if !strings.Contains(spanText(chat[:1]), "pantherclaw.simulated") {
		t.Fatal("simulated decide span is unmarked")
	}
	ev := chat[1].GetEvents()[0].GetAttributes()
	if len(ev) != 2 || ev[1].GetKey() != "pantherclaw.simulated" || !ev[1].GetValue().GetBoolValue() {
		t.Fatalf("simulated effect: %+v", ev)
	}
}

// TestHR788_ExportSpanIDsAreIdempotent: the same transaction exports the
// same span ids, and a transaction without a traceparent uses
// SHA-256(run id) with no parent.
// Covers: HR-788
func TestHR788_ExportSpanIDsAreIdempotent(t *testing.T) {
	row := sampleRow(false)
	a := transactionSpans("", row, nil)
	b := transactionSpans("", row, nil)
	if !bytes.Equal(a[0].GetSpanId(), b[0].GetSpanId()) || !bytes.Equal(a[1].GetSpanId(), b[1].GetSpanId()) {
		t.Fatal("re-export changed span ids")
	}
	if !bytes.Equal(a[0].GetSpanId(), spanID(row.ID, kindDecide)) || !bytes.Equal(a[1].GetSpanId(), spanID(row.ID, kindDispatch)) {
		t.Fatal("span id is not SHA-256(transaction id + kind)")
	}
	traceID, parent, flags := traceOf(row)
	sum := sha256.Sum256(row.RunID[:])
	if parent != nil || flags != 0 || !bytes.Equal(traceID, sum[:16]) {
		t.Fatalf("derived trace: %x parent %x flags %d", traceID, parent, flags)
	}
	row.TraceID = bytes.Repeat([]byte{0x11}, 16)
	row.ParentSpanID = bytes.Repeat([]byte{0x22}, 8)
	traceID, parent, _ = traceOf(row)
	if !bytes.Equal(traceID, row.TraceID) || !bytes.Equal(parent, row.ParentSpanID) {
		t.Fatal("agent trace was replaced")
	}
	other := sampleRow(false)
	other.ID = ids.NewV7()
	if bytes.Equal(transactionSpans("", other, nil)[0].GetSpanId(), a[0].GetSpanId()) {
		t.Fatal("two transactions share a span id")
	}
}

func sampleRow(simulated bool) dbq.OTLPSpanTransactionsRow {
	ms := int32(15)
	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	return dbq.OTLPSpanTransactionsRow{
		ID: mustUUID("01920000-0000-7000-8000-0000000000aa"), RunID: mustUUID("01920000-0000-7000-8000-0000000000bb"),
		AgentID:   mustUUID("01920000-0000-7000-8000-0000000000cc"),
		Operation: "github.pulls.merge", Channel: "mcp", Decision: "HOLD", ReasonCode: "APPROVAL_REQUIRED",
		Simulated: simulated, CreatedAt: at, DecidedAt: at.Add(time.Second),
		DispatchOutcome: "succeeded", DispatchMs: &ms, DispatchedAt: at.Add(2 * time.Second),
	}
}

func assertKeys(t *testing.T, name string, attrs []*commonv1.KeyValue, want map[string]bool) {
	t.Helper()
	if len(attrs) != len(want) {
		t.Errorf("%s: %d keys, want %d (%v)", name, len(attrs), len(want), keys(attrs))
	}
	for _, a := range attrs {
		if !want[a.GetKey()] {
			t.Errorf("%s: unexpected %s", name, a.GetKey())
		}
	}
}

func keys(attrs []*commonv1.KeyValue) []string {
	out := make([]string, len(attrs))
	for i, a := range attrs {
		out[i] = a.GetKey()
	}
	return out
}

func mustUUID(s string) ids.UUID {
	id, err := ids.ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return id
}

func spanText(spans []*tracev1.Span) string {
	var b strings.Builder
	for _, s := range spans {
		b.WriteString(s.GetName())
		for _, a := range s.GetAttributes() {
			b.WriteString(" ")
			b.WriteString(a.GetKey())
			b.WriteString("=")
			b.WriteString(a.GetValue().GetStringValue())
		}
	}
	return b.String()
}

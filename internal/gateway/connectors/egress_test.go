// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectors

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sandbox/edge"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

const egressID = "00000000-0000-7000-8000-0000000000e1"

type staticConfig struct{ cfg *control.Config }

func (s staticConfig) Current() *control.Config { return s.cfg }

// sent records the mediated requests the engine would send.
type sent struct {
	mu   sync.Mutex
	got  []actionir.Parsed
	txns []string
}

func (s *sent) ConnectorEgress(_ context.Context, _ *control.Connection, a actionir.Parsed, txn string) (egress.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got, s.txns = append(s.got, a), append(s.txns, txn)
	return egress.Response{Status: http.StatusOK, ContentType: "application/json", Body: []byte(`{"id":"re_1"}`)}, nil
}

// TestHR086_AConnectorsEgressIsBoundToTheCallInFlight: the egress
// listener takes a request only with a running connector's binding token,
// while a call to it is in flight, when it maps through the connector's
// egress connection to the call's own operation and target; it then goes
// out with the call's transaction. Anything else is refused by the
// gateway (G0 M9 design decision 6).
func TestHR086_AConnectorsEgressIsBoundToTheCallInFlight(t *testing.T) {
	p, err := manifest.Decode(mockpayments.Package)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	payments := &control.Connection{
		GatewayConnection: &pb.GatewayConnection{Id: egressID, Name: "payments", Kind: "http", BaseUrl: "https://payments.example.test"},
		Package:           p, Mapper: m,
	}
	cfg := &control.Config{Org: "00000000-0000-7000-8000-000000000001", ByID: map[string]*control.Connection{egressID: payments}}
	out := &sent{}
	s := &Supervisor{conf: staticConfig{cfg}, log: pclog.Discard(), running: map[string]*instance{}, send: out}
	s.running["conn-1"] = &instance{connection: "conn-1", binding: "binding-1", egress: egressID, done: make(chan struct{})}
	ctx := mapping.Context{
		Org: cfg.Org, Env: "00000000-0000-7000-8000-000000000002", RunID: "00000000-0000-7000-8000-000000000003",
		ActionID: "00000000-0000-7000-8000-000000000004", AgentInstance: "00000000-0000-7000-8000-000000000005", Connection: egressID,
	}
	refund := []byte(`{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`)
	call, err := m.HTTP(t.Context(), ctx, http.MethodPost, "/v1/refunds", "", refund)
	if err != nil {
		t.Fatal(err)
	}
	h := s.egressHandler()
	send := func(binding string, req edge.Egress) *httptest.ResponseRecorder {
		b, _ := json.Marshal(req)
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, edge.EgressPath, bytes.NewReader(b))
		if binding != "" {
			r.Header.Set(edge.HeaderBinding, binding)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	same := edge.Egress{Connection: "payments", Method: http.MethodPost, Host: "payments.example.test", Path: "/v1/refunds", Body: refund}
	other := edge.Egress{
		Connection: "payments", Method: http.MethodPost, Path: "/v1/refunds",
		Body: []byte(`{"charge":"ch_2","amount":"30.00","currency":"USD","reason":"duplicate"}`),
	}

	if w := send("binding-1", same); w.Code != http.StatusForbidden || !bytes.Contains(w.Body.Bytes(), []byte(codeNotInFlight)) {
		t.Fatalf("with no call in flight: %d %s", w.Code, w.Body)
	}
	land := s.Fly("conn-1", dispatch.Flight{Txn: "txn-1", Action: call.Action})
	if w := send("binding-1", same); w.Code != http.StatusOK || w.Body.String() != `{"id":"re_1"}` {
		t.Fatalf("the call's own request: %d %s", w.Code, w.Body)
	}
	for name, tc := range map[string]struct {
		binding string
		req     edge.Egress
		code    string
	}{
		"no binding":            {"", same, codeUnknownBinding},
		"another binding":       {"binding-2", same, codeUnknownBinding},
		"another charge":        {"binding-1", other, codeOutsideTheCall},
		"another target's read": {"binding-1", edge.Egress{Connection: "payments", Method: http.MethodGet, Path: "/v1/refunds/re_9"}, codeOutsideTheCall},
		"an unmapped route":     {"binding-1", edge.Egress{Connection: "payments", Method: http.MethodDelete, Path: "/v1/refunds"}, codeUnmapped},
		"another connection":    {"binding-1", edge.Egress{Connection: "github", Method: http.MethodPost, Path: "/v1/refunds", Body: refund}, codeUnmapped},
	} {
		w := send(tc.binding, tc.req)
		if w.Code/100 != 4 || !bytes.Contains(w.Body.Bytes(), []byte(tc.code)) || w.Header().Get(edge.HeaderRefusedBy) != "gateway" {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	land()
	if w := send("binding-1", same); w.Code != http.StatusForbidden {
		t.Fatalf("after the call landed: %d", w.Code)
	}
	out.mu.Lock()
	defer out.mu.Unlock()
	if len(out.got) != 1 || out.txns[0] != "txn-1" || out.got[0].Action.Operation != "payments.refund.create" {
		t.Fatalf("sent %d requests: %v", len(out.got), out.txns)
	}

	// A reviewed read of the call's own target is within the call; a read
	// of another target, or another write on it, is not.
	charge := call.Action.Target
	for _, tc := range []struct {
		op     string
		target actionir.Target
		want   bool
	}{
		{"payments.refund.list", charge, true},
		{"payments.refund.list", actionir.Target{Type: charge.Type, ID: "ch_2"}, false},
		{"payments.refund.unknown", charge, false},
	} {
		if got := within(payments, actionir.ActionIR{Operation: tc.op, Target: tc.target}, call.Action); got != tc.want {
			t.Errorf("within(%s on %s) = %v", tc.op, tc.target.ID, got)
		}
	}
}

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectors

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
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

const (
	egressID    = "00000000-0000-7000-8000-0000000000e1"
	connectorID = "00000000-0000-7000-8000-0000000000c1"
)

type staticConfig struct{ cfg *control.Config }

func (s staticConfig) Current() *control.Config { return s.cfg }

// sent records the mediated requests the engine would send.
type sent struct {
	mu      sync.Mutex
	got     []actionir.Parsed
	flights []dispatch.Flight
}

func (s *sent) ConnectorEgress(_ context.Context, _ *control.Connection, a actionir.Parsed, f dispatch.Flight) (egress.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got, s.flights = append(s.got, a), append(s.flights, f)
	return egress.Response{Status: http.StatusOK, ContentType: "application/json", Body: []byte(`{"id":"re_1"}`)}, nil
}

func (s *sent) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

// egressRig is a supervisor with one running connector whose egress goes
// through the mock payments package, which here also lets a connector
// list a charge's refunds over HTTP (a reviewed read).
type egressRig struct {
	s    *Supervisor
	out  *sent
	in   *instance
	m    *mapping.Mapper
	ids  mapping.Context
	conn *control.Connection
}

func newEgressRig(t *testing.T) *egressRig {
	t.Helper()
	p, err := manifest.Decode(mockpayments.Package)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := p.Definition("payments.refund.list")
	list.Mappings = append(list.Mappings, domain.Mapping{
		Channel: domain.ChannelHTTP, Method: http.MethodGet, Path: "/v1/refunds", Route: "payments-refund-list",
		Extract: domain.Extract{TargetID: "query.charge", Params: map[string]string{}},
	})
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
	stdin, _ := io.Pipe()
	stdout, _ := io.Pipe()
	t.Cleanup(func() { _, _ = stdin.Close(), stdout.Close() })
	in := &instance{
		connection: connectorID, binding: "binding-1", egress: egressID, done: make(chan struct{}), calls: make(chan struct{}, 1),
		stdio: NewStdio(io.Discard, stdout, 0),
	}
	s.running[connectorID] = in
	return &egressRig{
		s: s, out: out, in: in, m: m, conn: &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: connectorID, Kind: Kind}},
		ids: mapping.Context{
			Org: cfg.Org, Env: "00000000-0000-7000-8000-000000000002", RunID: "00000000-0000-7000-8000-000000000003",
			ActionID: "00000000-0000-7000-8000-000000000004", AgentInstance: "00000000-0000-7000-8000-000000000005", Connection: connectorID,
		},
	}
}

// call is the action the agent's call to the connector was authorized for:
// a refund through the connector's MCP tool.
func (r *egressRig) call(t *testing.T, amount string) actionir.Parsed {
	t.Helper()
	a, err := r.m.MCP(t.Context(), r.ids, "create_refund",
		[]byte(`{"charge":"ch_1","amount":"`+amount+`","currency":"USD","reason":"duplicate"}`))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (r *egressRig) send(t *testing.T, binding string, req edge.Egress) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(req)
	hr := httptest.NewRequestWithContext(t.Context(), http.MethodPost, edge.EgressPath, bytes.NewReader(b))
	if binding != "" {
		hr.Header.Set(edge.HeaderBinding, binding)
	}
	w := httptest.NewRecorder()
	r.s.egressHandler().ServeHTTP(w, hr)
	return w
}

func refund(charge, amount string) edge.Egress {
	return edge.Egress{
		Connection: "payments", Method: http.MethodPost, Host: "payments.example.test", Path: "/v1/refunds",
		Body: []byte(`{"charge":"` + charge + `","amount":"` + amount + `","currency":"USD","reason":"duplicate"}`),
	}
}

func refused(w *httptest.ResponseRecorder, code string) bool {
	return w.Code/100 == 4 && bytes.Contains(w.Body.Bytes(), []byte(`"`+code+`"`)) && w.Header().Get(edge.HeaderRefusedBy) == "gateway"
}

// TestHR086_AConnectorWritesOnlyTheAuthorizedActionOnce: while a call to a
// connector is in flight, its egress may send the call's authorized
// action exactly (the same action hash: target, canonical parameters,
// destinations and ids), once, and read the call's target through
// reviewed access: read operations. A 5000.00 refund during a call
// authorized for 30.00 is refused, a second identical refund is refused,
// and a read of the charge's refunds goes out; other charges, other
// targets' reads, unmapped requests and requests outside a call are
// refused, and each goes out with the call's transaction (G0 M9 design
// decision 6, founder decision 2026-10-11).
func TestHR086_AConnectorWritesOnlyTheAuthorizedActionOnce(t *testing.T) {
	r := newEgressRig(t)
	call := r.call(t, "30.00")
	read := edge.Egress{Connection: "payments", Method: http.MethodGet, Path: "/v1/refunds", Query: "charge=ch_1"}

	if w := r.send(t, "binding-1", refund("ch_1", "30.00")); !refused(w, codeNotInFlight) {
		t.Fatalf("with no call in flight: %d %s", w.Code, w.Body)
	}
	land, err := r.s.Fly(t.Context(), connectorID, dispatch.Flight{Txn: "txn-1", Action: call, Epoch: 7, Connector: r.conn})
	if err != nil {
		t.Fatal(err)
	}
	if w := r.send(t, "binding-1", refund("ch_1", "5000.00")); !refused(w, codeOutsideTheCall) {
		t.Fatalf("a 5000.00 refund on a 30.00 authorization: %d %s", w.Code, w.Body)
	}
	if w := r.send(t, "binding-1", refund("ch_1", "30.00")); w.Code != http.StatusOK || w.Body.String() != `{"id":"re_1"}` {
		t.Fatalf("the authorized refund: %d %s", w.Code, w.Body)
	}
	if w := r.send(t, "binding-1", refund("ch_1", "30.00")); !refused(w, codeRepeatedWrite) {
		t.Fatalf("the same refund again: %d %s", w.Code, w.Body)
	}
	if w := r.send(t, "binding-1", read); w.Code != http.StatusOK {
		t.Fatalf("a read of the charge's refunds: %d %s", w.Code, w.Body)
	}
	for name, tc := range map[string]struct {
		binding string
		req     edge.Egress
		code    string
	}{
		"no binding":            {"", refund("ch_1", "30.00"), codeUnknownBinding},
		"another binding":       {"binding-2", refund("ch_1", "30.00"), codeUnknownBinding},
		"another charge":        {"binding-1", refund("ch_2", "30.00"), codeOutsideTheCall},
		"another charge's read": {"binding-1", edge.Egress{Connection: "payments", Method: http.MethodGet, Path: "/v1/refunds", Query: "charge=ch_2"}, codeOutsideTheCall},
		"another target's read": {"binding-1", edge.Egress{Connection: "payments", Method: http.MethodGet, Path: "/v1/refunds/re_9"}, codeOutsideTheCall},
		"an unmapped route":     {"binding-1", edge.Egress{Connection: "payments", Method: http.MethodDelete, Path: "/v1/refunds"}, codeUnmapped},
		"another connection":    {"binding-1", edge.Egress{Connection: "github", Method: http.MethodPost, Path: "/v1/refunds"}, codeUnmapped},
	} {
		if w := r.send(t, tc.binding, tc.req); !refused(w, tc.code) {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	land()
	if w := r.send(t, "binding-1", read); !refused(w, codeNotInFlight) {
		t.Fatalf("after the call landed: %d", w.Code)
	}
	r.out.mu.Lock()
	defer r.out.mu.Unlock()
	if len(r.out.got) != 2 || r.out.got[0].Action.Operation != "payments.refund.create" || r.out.got[1].Action.Operation != "payments.refund.list" {
		t.Fatalf("sent %d requests", len(r.out.got))
	}
	for _, f := range r.out.flights {
		if f.Txn != "txn-1" || f.Epoch != 7 || f.Connector != r.conn {
			t.Fatalf("sent under %+v", f)
		}
	}
}

// TestHR086_AConnectorsEgressIsBoundToOneCallAtATime: a second call to a
// connector waits for the first to land, so the first call's egress is
// never judged against, or sent under, the second's action; a call that
// cannot wait is not sent, a broken connector takes no call, and each
// call's write is its own (G0 M9 design decision 6).
func TestHR086_AConnectorsEgressIsBoundToOneCallAtATime(t *testing.T) {
	r := newEgressRig(t)
	first, second := r.call(t, "30.00"), r.call(t, "40.00")
	land, err := r.s.Fly(t.Context(), connectorID, dispatch.Flight{Txn: "txn-1", Action: first, Connector: r.conn})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := r.s.Fly(ctx, connectorID, dispatch.Flight{Txn: "txn-2", Action: second, Connector: r.conn}); err == nil {
		t.Fatal("a second call flew while the first was in flight")
	}
	flown := make(chan func(), 1)
	go func() {
		l, err := r.s.Fly(t.Context(), connectorID, dispatch.Flight{Txn: "txn-2", Action: second, Connector: r.conn})
		if err != nil {
			t.Error(err)
			close(flown)
			return
		}
		flown <- l
	}()
	if w := r.send(t, "binding-1", refund("ch_1", "40.00")); !refused(w, codeOutsideTheCall) {
		t.Fatalf("the waiting call's refund under the first call: %d %s", w.Code, w.Body)
	}
	if w := r.send(t, "binding-1", refund("ch_1", "30.00")); w.Code != http.StatusOK {
		t.Fatalf("the first call's refund: %d %s", w.Code, w.Body)
	}
	land()
	land2 := <-flown
	if land2 == nil {
		t.FailNow()
	}
	if w := r.send(t, "binding-1", refund("ch_1", "30.00")); !refused(w, codeOutsideTheCall) {
		t.Fatalf("the first call's refund under the second: %d %s", w.Code, w.Body)
	}
	if w := r.send(t, "binding-1", refund("ch_1", "40.00")); w.Code != http.StatusOK {
		t.Fatalf("the second call's refund: %d %s", w.Code, w.Body)
	}
	land2()
	r.out.mu.Lock()
	if len(r.out.flights) != 2 || r.out.flights[0].Txn != "txn-1" || r.out.flights[1].Txn != "txn-2" {
		t.Errorf("sent under %+v", r.out.flights)
	}
	r.out.mu.Unlock()

	r.in.stdio.Close()
	if _, err := r.s.Fly(t.Context(), connectorID, dispatch.Flight{Txn: "txn-3", Action: first, Connector: r.conn}); err == nil {
		t.Fatal("a broken connector took a call")
	}
}

// TestHR086_AConnectorsReadsAreBounded: a call's egress reads at most
// maxReads times.
func TestHR086_AConnectorsReadsAreBounded(t *testing.T) {
	r := newEgressRig(t)
	land, err := r.s.Fly(t.Context(), connectorID, dispatch.Flight{Txn: "txn-1", Action: r.call(t, "30.00"), Connector: r.conn})
	if err != nil {
		t.Fatal(err)
	}
	defer land()
	read := edge.Egress{Connection: "payments", Method: http.MethodGet, Path: "/v1/refunds", Query: "charge=ch_1"}
	for range maxReads {
		if w := r.send(t, "binding-1", read); w.Code != http.StatusOK {
			t.Fatalf("read: %d %s", w.Code, w.Body)
		}
	}
	if w := r.send(t, "binding-1", read); !refused(w, codeTooManyReads) || r.out.count() != maxReads {
		t.Fatalf("read %d: %d %s", maxReads+1, w.Code, w.Body)
	}
}

// TestHR086_AReadIsOnlyASafeMethod: a reviewed access: read operation is a
// read of the call's target only over GET or HEAD; over another method it
// is judged as a write, so it goes out only if it is the call's action.
func TestHR086_AReadIsOnlyASafeMethod(t *testing.T) {
	r := newEgressRig(t)
	call := r.call(t, "30.00")
	read, err := r.m.HTTP(t.Context(), r.ids, http.MethodGet, "/v1/refunds", "charge=ch_1", nil)
	if err != nil {
		t.Fatal(err)
	}
	payments := r.s.conf.Current().ByID[egressID]
	for method, want := range map[string]bool{http.MethodGet: true, http.MethodHead: true, http.MethodPost: false, http.MethodDelete: false} {
		if write, ok := admit(payments, method, read, call); ok != want || (method == http.MethodGet && write) {
			t.Errorf("a read over %s: write %v, within %v", method, write, ok)
		}
	}
}
